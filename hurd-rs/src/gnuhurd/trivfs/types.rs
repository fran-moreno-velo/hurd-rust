//===========================================================================//
// crate::hurd::trivfs                                                       //
//---------------------------------------------------------------------------//
// From github - gnuhurd                                                     //
// /hurd/libtrivfs/trivfs.h                                                  //
//===========================================================================//

// Import types

use crate::gnumach::port::mach_port_t;
use crate::gnumach::kern_return::kern_return_t;
use crate::gnumach::error::mach_error_t;
use crate::gnumach::message::mach_msg_type_name_t;
use crate::gnumach::message::mach_msg_type_number_t;

use crate::gnuhurd::io::iouser;
use crate::gnuhurd::types::pthread_mutex_t;
use crate::gnuhurd::types::pthread_cond_t;
use crate::gnuhurd::types::fsys_t;
use crate::gnumach::todo::retry_type;
use crate::gnumach::error::EOPNOTSUPP;

use crate::gnuhurd::types::refcount_t;
use crate::gnuhurd::ports::port_info_t;
use crate::gnuhurd::ports::port_class_t;
use crate::gnuhurd::ports::port_bucket_t;

use std::ffi::{c_int,c_void,c_char};
use std::mem::{offset_of, size_of};
use std::sync::atomic::{AtomicI32, AtomicU32, Ordering};
use libc::uid_t;

//---------------------------------------------------------------------------//
// Safe accessors                                                              //
//---------------------------------------------------------------------------//

impl trivfs_protid_t {
    pub fn openmodes(&self) -> Result<c_int, kern_return_t> {
        if self.po.is_null() { Err(EOPNOTSUPP) }
        else { Ok(unsafe { self.po.read().openmodes_load() }) }
    }
    pub fn hook_ptr(&self) -> Result<*mut c_void, kern_return_t> {
        if self.po.is_null() { Err(EOPNOTSUPP) }
        else { Ok(unsafe { self.po.read().hook }) }
    }
    pub fn po_ref(&self) -> Result<&trivfs_peropen_t, kern_return_t> {
        unsafe { self.po.as_ref().ok_or(EOPNOTSUPP) }
    }
    pub fn po_ref_mut(&mut self) -> Result<&mut trivfs_peropen_t, kern_return_t> {
        unsafe { self.po.as_mut().ok_or(EOPNOTSUPP) }
    }
}


impl trivfs_control_t {
    pub fn bucket(&self) -> *mut port_bucket_t { self.pi.bucket }
}

impl trivfs_peropen_t {
    pub fn openmodes_load(&self) -> c_int {
        let a = unsafe { &*(&self.openmodes as *const _ as *const AtomicI32) };
        a.load(Ordering::Acquire)
    }
    pub fn openmodes_store(&self, v: c_int) {
        let a = unsafe { &*(&self.openmodes as *const _ as *const AtomicI32) };
        a.store(v, Ordering::Relaxed);
    }
    pub fn ref_init(&self, value: u32) {
        let a = unsafe { &*(&self.refcnt as *const _ as *const AtomicU32) };
        a.store(value, Ordering::Release);
    }
    pub fn ref_inc(&self) -> u32 {
        let a = unsafe { &*(&self.refcnt as *const _ as *const AtomicU32) };
        a.fetch_add(1, Ordering::AcqRel).wrapping_add(1) as u32
    }
    pub fn ref_dec(&self) -> u32 {
        let a = unsafe { &*(&self.refcnt as *const _ as *const AtomicU32) };
        a.fetch_sub(1, Ordering::AcqRel).wrapping_sub(1) as u32
    }
    pub fn references(&self) -> u32 {
        let a = unsafe { &*(&self.refcnt as *const _ as *const AtomicU32) };
        a.load(Ordering::Acquire)
    }
}


//---------------------------------------------------------------------------//
// Public types                                                              //
//---------------------------------------------------------------------------//

#[repr(C)]
#[derive(Copy, Clone)]
pub struct rlock_list { _unused: [u8; 0] }

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct rlock_peropen { pub locks: *mut *mut rlock_list }

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct rlock_box { pub locks: *mut rlock_list }

#[repr(C)]
#[derive(Copy, Clone)]
pub struct transbox {
    pub active: fsys_t,
    pub lock:   *mut pthread_mutex_t,
    pub flags:  c_int,
    pub wakeup: pthread_cond_t,
    pub cookie: *mut c_void,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct trivfs_protid_t {
    pub pi: port_info_t,
    pub user: *mut iouser,
    pub isroot: c_int,
    pub realnode: mach_port_t,
    pub hook: *mut c_void,
    pub po: *mut trivfs_peropen_t
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct trivfs_peropen_t {
    pub hook: *mut c_void,
    pub openmodes: c_int,
    pub refcnt: refcount_t,
    pub cntl: *mut trivfs_control_t,
    pub lock_status: rlock_peropen,
    pub tp: *mut trivfs_node_t
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct trivfs_node_t {
    pub lock: pthread_mutex_t,
    pub references: c_int,
    pub transbox: transbox,
    pub credlock: rlock_box,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct trivfs_control_t {
    pub pi: port_info_t,
    pub protid_class: *mut port_class_t,
    pub protid_bucket: *mut port_bucket_t,
    pub filesys_id: mach_port_t,
    pub file_id: mach_port_t,
    pub underlying: mach_port_t,
    pub hook: *mut c_void
}

pub type trivfs_getroot_hook_fun = Option<unsafe extern "C-unwind" fn(
        cntl: *mut trivfs_control_t,
        reply_port: mach_port_t,
        reply_port_type: mach_msg_type_name_t,
        dotdot: mach_port_t,
        uids: *const uid_t,
        nuids: mach_msg_type_number_t,
        gids: *const uid_t,
        ngids: mach_msg_type_number_t,
        flags: c_int,
        do_retry: *mut retry_type,
        retry_name: *mut c_char,
        node: *mut mach_port_t,
        node_type: *mut mach_msg_type_name_t,
    ) -> mach_error_t >;

//---------------------------------------------------------------------------//
// Asserts                                                                   //
//---------------------------------------------------------------------------//

const _: () = {
    // one line per invariant; if the condition is false, index=1 → out of bounds → const error
    ["transbox.cookie layout mismatch"]
        [(offset_of!(transbox, cookie) != offset_of!(transbox, wakeup) + size_of::<pthread_cond_t>()) as usize];
    ["peropen.tp layout mismatch"]
        [(offset_of!(trivfs_peropen_t, tp) != offset_of!(trivfs_peropen_t, lock_status) + size_of::<rlock_peropen>()) as usize];
    ["node.credlock layout mismatch"]
        [(offset_of!(trivfs_node_t, credlock) != offset_of!(trivfs_node_t, transbox) + size_of::<transbox>()) as usize];
    ["node.references layout mismatch"]
        [(offset_of!(trivfs_node_t, references) != offset_of!(trivfs_node_t, lock) + size_of::<pthread_mutex_t>()) as usize];
};

#[cfg(test)]
mod tests {
    use super::*;

    // #5: openmodes is accessed atomically (by address, without changing the
    // C layout of trivfs_peropen_t). Round-trip store/load.
    #[test]
    fn openmodes_atomic_roundtrip() {
        let po: trivfs_peropen_t = unsafe { std::mem::zeroed() };
        po.openmodes_store(0);
        assert_eq!(po.openmodes_load(), 0);
        po.openmodes_store(0o777);
        assert_eq!(po.openmodes_load(), 0o777);
        po.openmodes_store(-1);
        assert_eq!(po.openmodes_load(), -1);
    }
}