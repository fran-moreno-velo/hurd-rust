use std::ffi::c_int;
use crate::gnuhurd::trivfs::hooks::Hook;
use crate::gnumach::kern_return::kern_return_t;
use crate::gnumach::port::mach_port_t;
use crate::gnumach::message::mach_msg_type_name_t;
use crate::gnumach::error::EOPNOTSUPP;
use crate::gnuhurd::trivfs::types::trivfs_protid_t;
use crate::gnumach::message::mach_msg_type_number_t;
use crate::gnuhurd::io::{loff_t, const_data_t};
use crate::gnuhurd::trivfs::hooks::load_check_access;
use crate::gnuhurd::trivfs::times;

// ── Function types ──

pub type IoReadableFn = unsafe extern "C-unwind" fn(
    cred: *mut trivfs_protid_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
    amount: *mut mach_msg_type_number_t,
) -> kern_return_t;

pub type IoGetOpenmodesFn = unsafe extern "C-unwind" fn(
    cred: *mut trivfs_protid_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
    bits: *mut c_int,
) -> kern_return_t;

pub type IoSetAllOpenmodesFn = unsafe extern "C-unwind" fn(
    cred: *mut trivfs_protid_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
    mode: c_int,
) -> kern_return_t;

pub type IoSetSomeOpenmodesFn = unsafe extern "C-unwind" fn(
    cred: *mut trivfs_protid_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
    bits: c_int,
) -> kern_return_t;

pub type IoClearSomeOpenmodesFn = unsafe extern "C-unwind" fn(
    cred: *mut trivfs_protid_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
    bits: c_int,
) -> kern_return_t;

pub type FileCheckAccessFn = unsafe extern "C-unwind" fn(
    cred: *mut trivfs_protid_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
    allowed: *mut c_int,
) -> kern_return_t;

pub type IoSelectFn = unsafe extern "C-unwind" fn(
    cred: *mut trivfs_protid_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
    ttype: *mut c_int
) -> kern_return_t;

pub type IoSelectTimeoutFn = unsafe extern "C-unwind" fn(
    cred: *mut trivfs_protid_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
    ts: *mut u8,
    seltype: *mut c_int,
) -> kern_return_t;

pub type IoSeekFn = unsafe extern "C-unwind" fn(
    cred: *mut trivfs_protid_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
    offset: loff_t,
    whence: c_int,
    newp: *mut loff_t,
) -> kern_return_t;

// ── Hooks ──

static IO_READABLE_HOOK: Hook<IoReadableFn> = Hook::new();
static IO_GET_OPENMODES_HOOK: Hook<IoGetOpenmodesFn> = Hook::new();
static IO_SET_ALL_OPENMODES_HOOK: Hook<IoSetAllOpenmodesFn> = Hook::new();
static IO_SET_SOME_OPENMODES_HOOK: Hook<IoSetSomeOpenmodesFn> = Hook::new();
static IO_CLEAR_SOME_OPENMODES_HOOK: Hook<IoClearSomeOpenmodesFn> = Hook::new();
static FILE_CHECK_ACCESS_HOOK: Hook<FileCheckAccessFn> = Hook::new();
static IO_SELECT_HOOK: Hook<IoSelectFn> = Hook::new();
static IO_SELECT_TIMEOUT_HOOK: Hook<IoSelectTimeoutFn> = Hook::new();
static IO_SEEK_HOOK: Hook<IoSeekFn> = Hook::new();

// ── Register API ──

pub fn register_io_readable(f: IoReadableFn) { let _ = IO_READABLE_HOOK.set(f); }
pub fn register_io_get_openmodes(f: IoGetOpenmodesFn) { let _ = IO_GET_OPENMODES_HOOK.set(f); }
pub fn register_io_set_all_openmodes(f: IoSetAllOpenmodesFn) { let _ = IO_SET_ALL_OPENMODES_HOOK.set(f); }
pub fn register_io_set_some_openmodes(f: IoSetSomeOpenmodesFn) { let _ = IO_SET_SOME_OPENMODES_HOOK.set(f); }
pub fn register_io_clear_some_openmodes(f: IoClearSomeOpenmodesFn) { let _ = IO_CLEAR_SOME_OPENMODES_HOOK.set(f); }
pub fn register_file_check_access(f: FileCheckAccessFn) { let _ = FILE_CHECK_ACCESS_HOOK.set(f); }
pub fn register_io_select_timeout(f: IoSelectTimeoutFn) { let _ = IO_SELECT_TIMEOUT_HOOK.set(f); }
pub fn register_io_select(f: IoSelectFn) { let _ = IO_SELECT_HOOK.set(f); }
pub fn register_io_seek(f: IoSeekFn) { let _ = IO_SEEK_HOOK.set(f); }

// ── linker-visible symbols ──

#[unsafe(no_mangle)]
pub unsafe extern "C-unwind" fn trivfs_S_io_readable(
    cred: *mut trivfs_protid_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
    amount: *mut mach_msg_type_number_t,
) -> kern_return_t {
    match IO_READABLE_HOOK.get() {
        Some(f) => f(cred, reply, replyPoly, amount),
        None => EOPNOTSUPP,
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C-unwind" fn trivfs_S_io_get_openmodes(
    cred: *mut trivfs_protid_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
    bits: *mut c_int,
) -> kern_return_t {
    match IO_GET_OPENMODES_HOOK.get() {
        Some(f) => f(cred, reply, replyPoly, bits),
        None => {
            if cred.is_null() { return EOPNOTSUPP; }
            let cred = unsafe { &*cred };
            *bits = match cred.openmodes() {
                Ok(v) => v,
                Err(e) => return e,
            };
            0
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C-unwind" fn trivfs_S_io_set_all_openmodes(
    cred: *mut trivfs_protid_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
    mode: c_int,
) -> kern_return_t {
    match IO_SET_ALL_OPENMODES_HOOK.get() {
        Some(f) => f(cred, reply, replyPoly, mode),
        None => EOPNOTSUPP,
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C-unwind" fn trivfs_S_io_set_some_openmodes(
    cred: *mut trivfs_protid_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
    bits: c_int,
) -> kern_return_t {
    match IO_SET_SOME_OPENMODES_HOOK.get() {
        Some(f) => f(cred, reply, replyPoly, bits),
        None => EOPNOTSUPP,
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C-unwind" fn trivfs_S_io_clear_some_openmodes(
    cred: *mut trivfs_protid_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
    bits: c_int,
) -> kern_return_t {
    match IO_CLEAR_SOME_OPENMODES_HOOK.get() {
        Some(f) => f(cred, reply, replyPoly, bits),
        None => EOPNOTSUPP,
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C-unwind" fn trivfs_S_file_check_access(
    cred: *mut trivfs_protid_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
    allowed: *mut c_int,
) -> kern_return_t {
    match FILE_CHECK_ACCESS_HOOK.get() {
        Some(f) => f(cred, reply, replyPoly, allowed),
        None => {
            if cred.is_null() { return EOPNOTSUPP; }
            let c = unsafe { &*cred };
            let cntl = match c.po_ref() { Ok(p) => p.cntl, Err(e) => return e };
            match load_check_access() {
                Some(f) => f(cntl, c.user, c.realnode, allowed),
                None => times::file_check_access(c.realnode, allowed),
            }
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C-unwind" fn trivfs_S_io_select(
    cred: *mut trivfs_protid_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
    ttype: *mut c_int,
) -> kern_return_t {
    match IO_SELECT_HOOK.get() {
        Some(f) => f(cred, reply, replyPoly, ttype),
        None => EOPNOTSUPP,
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C-unwind" fn trivfs_S_io_select_timeout(
    cred: *mut trivfs_protid_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
    ts: *mut u8,
    seltype: *mut c_int,
) -> kern_return_t {
    match IO_SELECT_TIMEOUT_HOOK.get() {
        Some(f) => f(cred, reply, replyPoly, ts, seltype),
        None => trivfs_S_io_select(cred, reply, replyPoly, seltype),
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C-unwind" fn trivfs_S_io_seek(
    cred: *mut trivfs_protid_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
    offset: loff_t,
    whence: c_int,
    newp: *mut loff_t,
) -> kern_return_t {
    match IO_SEEK_HOOK.get() {
        Some(f) => f(cred, reply, replyPoly, offset, whence, newp),
        None => EOPNOTSUPP,
    }
}

// ── FileSetTranslatorFn ──
pub type FileSetTranslatorFn = unsafe extern "C-unwind" fn(
    file: *mut trivfs_protid_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
    passive_flags: c_int,
    active_flags: c_int,
    oldtrans_flags: c_int,
    passive: const_data_t,
    passiveCnt: mach_msg_type_number_t,
    active: mach_port_t,
) -> kern_return_t;

static FILE_SET_TRANSLATOR_HOOK: Hook<FileSetTranslatorFn> = Hook::new();
pub fn register_file_set_translator(f: FileSetTranslatorFn) { let _ = FILE_SET_TRANSLATOR_HOOK.set(f); }

#[unsafe(no_mangle)]
pub unsafe extern "C-unwind" fn trivfs_S_file_set_translator(
    file: *mut trivfs_protid_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
    passive_flags: c_int,
    active_flags: c_int,
    oldtrans_flags: c_int,
    passive: const_data_t,
    passiveCnt: mach_msg_type_number_t,
    active: mach_port_t,
) -> kern_return_t {
    match FILE_SET_TRANSLATOR_HOOK.get() {
        Some(f) => f(file, reply, replyPoly, passive_flags, active_flags, oldtrans_flags, passive, passiveCnt, active),
        None => EOPNOTSUPP,
    }
}