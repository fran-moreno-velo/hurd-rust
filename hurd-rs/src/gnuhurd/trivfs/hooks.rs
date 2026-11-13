use std::ffi::{c_char, c_int};
use crate::gnumach::error::mach_error_t;
use crate::gnumach::port::mach_port_t;
use crate::gnumach::message::{mach_msg_type_name_t, mach_msg_type_number_t};
use crate::gnumach::todo::retry_type;
use crate::gnuhurd::io::iouser;
use crate::gnuhurd::trivfs::types::{
    trivfs_control_t, trivfs_peropen_t, trivfs_protid_t, trivfs_getroot_hook_fun,
};
use libc::uid_t;
use std::marker::PhantomData;
use std::sync::atomic::{AtomicPtr, Ordering};

// --- Statics ---- //

#[unsafe(no_mangle)]
pub static mut trivfs_check_access_hook: Option<unsafe extern "C-unwind" fn(
    cntl: *mut trivfs_control_t, user: *mut iouser, realnode: mach_port_t, allowed: *mut c_int,
) -> mach_error_t> = None;

#[unsafe(no_mangle)]
pub static mut trivfs_check_open_hook: Option<unsafe extern "C-unwind" fn(
    cntl: *mut trivfs_control_t, user: *mut iouser, flags: c_int,
) -> mach_error_t> = None;

#[unsafe(no_mangle)]
pub static mut trivfs_open_hook: Option<unsafe extern "C-unwind" fn(
    fsys: *mut trivfs_control_t, user: *mut iouser, dotdot: mach_port_t, flags: c_int,
    realnode: mach_port_t, cred: *mut *mut trivfs_protid_t,
) -> mach_error_t> = None;

#[unsafe(no_mangle)]
pub static mut trivfs_protid_create_hook: Option<unsafe extern "C-unwind" fn(
    newcred: *mut trivfs_protid_t,
) -> mach_error_t> = None;

#[unsafe(no_mangle)]
pub static mut trivfs_peropen_create_hook: Option<unsafe extern "C-unwind" fn(
    po: *mut trivfs_peropen_t,
) -> mach_error_t> = None;

#[unsafe(no_mangle)]
pub static mut trivfs_protid_destroy_hook: Option<unsafe extern "C-unwind" fn(
    newcred: *mut trivfs_protid_t,
)> = None;

#[unsafe(no_mangle)]
pub static mut trivfs_peropen_destroy_hook: Option<unsafe extern "C-unwind" fn(
    po: *mut trivfs_peropen_t,
)> = None;

#[unsafe(no_mangle)]
pub static mut trivfs_getroot_hook: trivfs_getroot_hook_fun = None;



// -- Registers -- //

/// Write an ABI hook (`static mut Option<fn>`) atomically (`store`
/// `Release`), symmetric to `load_fptr`. Option<fn> and *mut () share
/// layout (NPO).
fn store_fptr<T: Copy>(slot: *mut Option<T>, f: Option<T>) {
    let p = match f {
        Some(f) => unsafe { std::mem::transmute_copy::<T, *mut ()>(&f) },
        None => std::ptr::null_mut(),
    };
    unsafe { AtomicPtr::from_ptr(slot as *mut *mut ()).store(p, Ordering::Release) };
}

pub fn register_trivfs_check_access(
    f: unsafe extern "C-unwind" fn(*mut trivfs_control_t, *mut iouser, mach_port_t, *mut c_int) -> mach_error_t,
) {
    store_fptr(&raw mut trivfs_check_access_hook, Some(f));
}

pub fn register_trivfs_check_open(
    f: unsafe extern "C-unwind" fn(*mut trivfs_control_t, *mut iouser, c_int) -> mach_error_t,
) {
    store_fptr(&raw mut trivfs_check_open_hook, Some(f));
}

pub fn register_trivfs_open(
    f: unsafe extern "C-unwind" fn(*mut trivfs_control_t, *mut iouser, mach_port_t, c_int, mach_port_t, *mut *mut trivfs_protid_t) -> mach_error_t,
) {
    store_fptr(&raw mut trivfs_open_hook, Some(f));
}

pub fn register_trivfs_protid_create(
    f: unsafe extern "C-unwind" fn(*mut trivfs_protid_t) -> mach_error_t,
) {
    store_fptr(&raw mut trivfs_protid_create_hook, Some(f));
}

pub fn register_trivfs_peropen_create(
    f: unsafe extern "C-unwind" fn(*mut trivfs_peropen_t) -> mach_error_t,
) {
    store_fptr(&raw mut trivfs_peropen_create_hook, Some(f));
}

pub fn register_trivfs_protid_destroy(
    f: unsafe extern "C-unwind" fn(*mut trivfs_protid_t),
) {
    store_fptr(&raw mut trivfs_protid_destroy_hook, Some(f));
}

pub fn register_trivfs_peropen_destroy(
    f: unsafe extern "C-unwind" fn(*mut trivfs_peropen_t),
) {
    store_fptr(&raw mut trivfs_peropen_destroy_hook, Some(f));
}

pub fn register_trivfs_getroot(
    f: unsafe extern "C-unwind" fn(
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
    ) -> mach_error_t,
) {
    store_fptr(&raw mut trivfs_getroot_hook, Some(f));
}

// --- Getters --- //

/// Read an ABI hook (static mut Option<fn>) atomically, without touching the
/// no_mangle symbol. Option<fn> and *mut () share layout (NPO).
fn load_fptr<T: Copy>(slot: *const Option<T>) -> Option<T> {
    let p = unsafe { AtomicPtr::from_ptr(slot as *mut *mut ()) }.load(Ordering::Acquire);
    if p.is_null() { None } else { Some(unsafe { std::mem::transmute_copy::<*mut (), T>(&p) }) }
}

pub fn load_check_access() -> Option<unsafe extern "C-unwind" fn(
    *mut trivfs_control_t, *mut iouser, mach_port_t, *mut c_int,
) -> mach_error_t> {
    load_fptr(&raw const trivfs_check_access_hook)
}

pub fn load_check_open() -> Option<unsafe extern "C-unwind" fn(
    *mut trivfs_control_t, *mut iouser, c_int,
) -> mach_error_t> {
    load_fptr(&raw const trivfs_check_open_hook)
}

pub fn load_open() -> Option<unsafe extern "C-unwind" fn(
    *mut trivfs_control_t, *mut iouser, mach_port_t, c_int, mach_port_t, *mut *mut trivfs_protid_t,
) -> mach_error_t> {
    load_fptr(&raw const trivfs_open_hook)
}

pub fn load_protid_create() -> Option<unsafe extern "C-unwind" fn(*mut trivfs_protid_t) -> mach_error_t> {
    load_fptr(&raw const trivfs_protid_create_hook)
}

pub fn load_peropen_create() -> Option<unsafe extern "C-unwind" fn(*mut trivfs_peropen_t) -> mach_error_t> {
    load_fptr(&raw const trivfs_peropen_create_hook)
}

pub fn load_protid_destroy() -> Option<unsafe extern "C-unwind" fn(*mut trivfs_protid_t)> {
    load_fptr(&raw const trivfs_protid_destroy_hook)
}

pub fn load_peropen_destroy() -> Option<unsafe extern "C-unwind" fn(*mut trivfs_peropen_t)> {
    load_fptr(&raw const trivfs_peropen_destroy_hook)
}

pub fn load_getroot() -> trivfs_getroot_hook_fun {
    load_fptr(&raw const trivfs_getroot_hook)
}


// --- Hook<T>: module-overwritable hooks without data race --- //

pub struct Hook<T> {
    ptr: AtomicPtr<()>,
    _marker: PhantomData<T>,
}

impl<T: Copy> Hook<T> {
    pub const fn new() -> Self {
        Hook {
            ptr: AtomicPtr::new(std::ptr::null_mut()),
            _marker: PhantomData,
        }
    }

    pub fn set(&self, f: T) {
        debug_assert_eq!(std::mem::size_of::<T>(), std::mem::size_of::<*mut ()>());
        let p = unsafe { std::mem::transmute_copy::<T, *mut ()>(&f) };
        self.ptr.store(p, Ordering::Release);
    }

    /// Unregister the hook (for configuration tests: a translator that
    /// declares `trivfs_support_*` without registering the matching hook).
    pub fn clear(&self) {
        self.ptr.store(std::ptr::null_mut(), Ordering::Release);
    }

    pub fn get(&self) -> Option<T> {
        let p = self.ptr.load(Ordering::Acquire);
        if p.is_null() {
            None
        } else {
            Some(unsafe { std::mem::transmute_copy::<*mut (), T>(&p) })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    unsafe extern "C" fn dummy_a() -> mach_error_t { 0 }
    unsafe extern "C" fn dummy_b() -> mach_error_t { 0 }

    fn fn_addr_eq(a: unsafe extern "C" fn() -> mach_error_t, b: unsafe extern "C" fn() -> mach_error_t) -> bool {
        a as usize == b as usize
    }

    #[test]
    fn hook_empty_then_set_and_get() {
        let h: Hook<unsafe extern "C" fn() -> mach_error_t> = Hook::new();
        assert!(h.get().is_none());
        h.set(dummy_a);
        assert!(fn_addr_eq(h.get().unwrap(), dummy_a));
    }

    #[test]
    fn hook_last_wins() {
        let h: Hook<unsafe extern "C" fn() -> mach_error_t> = Hook::new();
        h.set(dummy_a);
        h.set(dummy_b);
        assert!(fn_addr_eq(h.get().unwrap(), dummy_b));
    }

    // #2: the register_* of the ABI hooks write with a `Release` store and the
    // `load_*` read with `Acquire` (symmetric store_fptr/load_fptr). Round-trip
    // on one ABI hook.
    unsafe extern "C-unwind" fn dummy_access(
        _c: *mut trivfs_control_t, _u: *mut iouser, _r: mach_port_t, _a: *mut c_int,
    ) -> mach_error_t { 0 }

    #[test]
    fn abi_hook_register_load_roundtrip() {
        assert!(load_check_access().is_none());
        register_trivfs_check_access(dummy_access);
        let f: unsafe extern "C-unwind" fn(
            *mut trivfs_control_t, *mut iouser, mach_port_t, *mut c_int,
        ) -> mach_error_t = dummy_access;
        assert!(load_check_access().unwrap() as usize == f as usize);
    }
}