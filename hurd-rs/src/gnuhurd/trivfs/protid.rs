use std::ffi::c_void;

use crate::gnumach::error::ERR_NONE;
use crate::gnumach::error::mach_error_t;
use crate::gnumach::port::MACH_PORT_NULL;
use crate::gnumach::port::MACH_PORT_RIGHT_SEND;
use crate::gnumach::port::mach_port_deallocate;
use crate::gnumach::port::mach_port_mod_refs;
use crate::gnumach::task::mach_task_self;
use crate::gnuhurd::ports::ports_create_port;
use crate::gnuhurd::ports::ports_port_deref;
use crate::gnuhurd::trivfs::types::{trivfs_peropen_t, trivfs_protid_t};
use crate::gnuhurd::trivfs::hooks::{load_protid_create, load_protid_destroy, load_peropen_destroy};
use crate::gnuhurd::io::{iohelp_dup_iouser, iohelp_free_iouser};
use crate::gnumach::error::ENULLPTR;

#[unsafe(no_mangle)]
pub unsafe extern "C" fn trivfs_protid_dup(
    cred: *mut trivfs_protid_t,
    dup: *mut *mut trivfs_protid_t,
) -> mach_error_t {
    let mut new: *mut trivfs_protid_t = std::ptr::null_mut();
    if cred.is_null() { return ENULLPTR; }
    let cntl = match unsafe { (&*cred).po_ref() } {
        Ok(po) => match po.cntl.as_ref() {
            Some(c) => c,
            None => return ENULLPTR,
        },
        Err(e) => return e,
    };
    let mut err = unsafe {
        ports_create_port(
            cntl.protid_class,
            cntl.protid_bucket,
            std::mem::size_of::<trivfs_protid_t>(),
            (&mut new) as *mut *mut trivfs_protid_t as *mut c_void,
        )
    };

    if err == ERR_NONE {
        unsafe {
            let new_ref = &mut *new;
            let cred_ref = &*cred;
            new_ref.po = cred_ref.po;
            match new_ref.po_ref_mut() {
                Ok(p) => { p.ref_inc(); }
                Err(e) => { ports_port_deref(new as *mut c_void); return e; }
            }
            new_ref.isroot = cred_ref.isroot;

            err = iohelp_dup_iouser(&mut new_ref.user, cred_ref.user);
            if err != ERR_NONE {
                ports_port_deref(new as *mut c_void);
                return err;
            }

            new_ref.realnode = cred_ref.realnode;
            // #11: the +1 balances the `realnode` dealloc in trivfs_clean_protid.
            // C ignores the return (protid-dup.c:50); if it failed (corrupt
            // realnode) the later dealloc would be unbalanced — pathological
            // edge, same invariant as C.
            let _ = mach_port_mod_refs(mach_task_self(), new_ref.realnode, MACH_PORT_RIGHT_SEND, 1);

            new_ref.hook = cred_ref.hook;

            if let Some(hook) = load_protid_create() {
                err = hook(new);
            }
            if err != ERR_NONE {
                mach_port_deallocate(mach_task_self(), new_ref.realnode);
                new_ref.realnode = MACH_PORT_NULL;
                ports_port_deref(new as *mut c_void);
            } else {
                *dup = new;
            }
        }
    }

    err
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn trivfs_clean_protid(arg: *mut c_void) {
    if arg.is_null() { return; }
    let cred = &mut *(arg as *mut trivfs_protid_t);
    let po_ptr = cred.po;
    if po_ptr.is_null() { return; }
    let cntl = unsafe { (*po_ptr).cntl };

    if let Some(hook) = load_protid_destroy() {
        if cred.realnode != MACH_PORT_NULL {
            unsafe { hook(arg as *mut trivfs_protid_t) };
        }
    }

    let po = unsafe { &mut *po_ptr };
    if let Some(hook) = load_peropen_destroy() {
        if po.ref_dec() == 0 {
            po.ref_inc();
            unsafe { hook(po_ptr) };
            if po.ref_dec() == 0 {
                unsafe {
                    ports_port_deref(cntl as *mut c_void);
                    std::alloc::dealloc(po_ptr as *mut u8, std::alloc::Layout::new::<trivfs_peropen_t>())
                }
            }
        }
    } else {
        if po.ref_dec() == 0 {
            unsafe {
                ports_port_deref(cntl as *mut c_void);
                std::alloc::dealloc(po_ptr as *mut u8, std::alloc::Layout::new::<trivfs_peropen_t>())
            }
        }
    }

    unsafe {
        iohelp_free_iouser(cred.user);
        if cred.realnode != MACH_PORT_NULL {
            mach_port_deallocate(mach_task_self(), cred.realnode);
        }
    }
}