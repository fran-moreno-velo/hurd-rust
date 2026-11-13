use std::ffi::{c_void, c_uint, c_int};
use std::alloc::{alloc, Layout};
use crate::gnumach::error::{ERR_NONE, mach_error_t};
use crate::gnumach::port::{mach_port_t, MACH_PORT_NULL};
use crate::gnuhurd::io::iouser;
use crate::gnuhurd::ports::{ports_create_port, ports_port_ref, ports_port_deref};
use crate::gnuhurd::trivfs::types::{trivfs_control_t, trivfs_peropen_t, trivfs_protid_t};
use crate::gnuhurd::trivfs::private;
use crate::gnuhurd::trivfs::hooks::{load_peropen_create, load_protid_create, load_peropen_destroy};
use crate::gnumach::error::{ENOMEM, ENULLPTR};

#[unsafe(no_mangle)]
pub unsafe extern "C" fn trivfs_open(
    cntl: *mut trivfs_control_t,
    user: *mut iouser,
    flags: c_uint,
    realnode: mach_port_t,
    cred: *mut *mut trivfs_protid_t,
) -> mach_error_t {
    if cntl.is_null() || user.is_null() || cred.is_null() { return ENULLPTR; }
    let layout = Layout::new::<trivfs_peropen_t>();
    let po = unsafe { alloc(layout) } as *mut trivfs_peropen_t;
    if po.is_null() { return ENOMEM; }

    ports_port_ref(cntl as *mut c_void);

    let peropen = unsafe { &mut *po };
    peropen.ref_init(1);                   // refcount_init(&peropen;->refcnt, 1)
    peropen.cntl = cntl;
    peropen.openmodes_store(flags as c_int);
    peropen.hook = std::ptr::null_mut();

    let mut err = ERR_NONE;
    if let Some(hook) = load_peropen_create() { err = hook(po); }
    if err == ERR_NONE {
        let cntl_ref = unsafe { &*cntl };
        let mut new: *mut trivfs_protid_t = std::ptr::null_mut();
        err = ports_create_port(
            cntl_ref.protid_class, cntl_ref.protid_bucket,
            std::mem::size_of::<trivfs_protid_t>(),
            (&mut new) as *mut *mut trivfs_protid_t as *mut c_void);
        if err == ERR_NONE {
            let new_ref = unsafe { &mut *new };
            let user_ref = unsafe { &*user };
            new_ref.user = user;
            new_ref.isroot = private::_is_privileged(user_ref.uids);
            new_ref.po = po;
            new_ref.hook = std::ptr::null_mut();
            new_ref.realnode = realnode;
            if let Some(hook) = load_protid_create() { err = hook(new); }
            if err != ERR_NONE {
                // `ports_port_deref(new)` synchronously runs
                // `trivfs_clean_protid`, which would free `po`, `cntl` and
                // `user`. We neutralize the protid so the cleanup happens only
                // once in the error block below (and the caller frees `user`).
                new_ref.po = std::ptr::null_mut();
                new_ref.user = std::ptr::null_mut();
                new_ref.realnode = MACH_PORT_NULL;
                ports_port_deref(new as *mut c_void);
            } else {
                *cred = new;
            }
        }
    }

    if err != ERR_NONE {
        if let Some(hook) = load_peropen_destroy() {
            unsafe { hook(po) };
        }
        ports_port_deref(cntl as *mut c_void);
        unsafe { std::alloc::dealloc(po as *mut u8, std::alloc::Layout::new::<trivfs_peropen_t>()) }
    }
    err
}