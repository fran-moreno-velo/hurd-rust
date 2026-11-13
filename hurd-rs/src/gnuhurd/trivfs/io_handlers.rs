use crate::gnuhurd::trivfs::hooks::Hook;
use crate::gnumach::kern_return::kern_return_t;
use crate::gnumach::port::mach_port_t;
use crate::gnumach::message::mach_msg_type_name_t;
use crate::gnumach::message::mach_msg_type_number_t;
use crate::gnumach::vm_types::vm_size_t;
use crate::gnumach::error::EOPNOTSUPP;
use crate::gnumach::error::mach_error_t;
use crate::gnumach::error::EBADF;
use crate::gnuhurd::trivfs::types::{trivfs_protid_t, trivfs_control_t};
use crate::gnuhurd::io::{data_t, const_data_t, loff_t, io_statbuf_t};
use crate::gnuhurd::trivfs::times;
use crate::gnuhurd::trivfs::symbols::{fsid, fstype, allow_open};
use crate::gnuhurd::fcntl::O_WRITE;
use crate::gnuhurd::mig_user::{io_revoke};

use std::ffi::c_int;

// ── Function types (exact prototype from trivfs.h:300-326) ──

pub type IoWriteFn = unsafe extern "C-unwind" fn(
    io_object: *mut trivfs_protid_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
    data: const_data_t,
    dataCnt: mach_msg_type_number_t,
    offset: loff_t,
    amount: *mut vm_size_t,
) -> kern_return_t;

pub type IoReadFn = unsafe extern "C-unwind" fn(
    io_object: *mut trivfs_protid_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
    data: *mut data_t,
    dataCnt: *mut mach_msg_type_number_t,
    offset: loff_t,
    amount: vm_size_t,
) -> kern_return_t;

pub type IoStatFn = unsafe extern "C-unwind" fn(
    stat_object: *mut trivfs_protid_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
    stat_info: *mut io_statbuf_t,
) -> kern_return_t;

pub type TrivfsModifyStatFn = unsafe extern "C-unwind" fn(
    cred: *mut trivfs_protid_t,
    st: *mut io_statbuf_t,
);

pub type TrivfsGoawayFn = unsafe extern "C-unwind" fn(cntl: *mut trivfs_control_t, flags: c_int) -> mach_error_t;

pub type IoRevokeFn = unsafe extern "C-unwind" fn(
    cred: *mut trivfs_protid_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
) -> kern_return_t;

// ── Hooks ──

static IO_WRITE_HOOK: Hook<IoWriteFn> = Hook::new();
static IO_READ_HOOK: Hook<IoReadFn> = Hook::new();
static IO_STAT_HOOK: Hook<IoStatFn> = Hook::new();
static MODIFY_STAT_HOOK: Hook<TrivfsModifyStatFn> = Hook::new();
static GOAWAY_HOOK: Hook<TrivfsGoawayFn> = Hook::new();
static IO_REVOKE_HOOK: Hook<IoRevokeFn> = Hook::new();

// ── Register API ──

pub fn register_io_write(f: IoWriteFn) { let _ = IO_WRITE_HOOK.set(f); }
pub fn register_io_read(f: IoReadFn)  { let _ = IO_READ_HOOK.set(f); }
pub fn io_write_registered() -> bool { IO_WRITE_HOOK.get().is_some() }
pub fn io_read_registered() -> bool { IO_READ_HOOK.get().is_some() }
pub fn clear_io_read() { IO_READ_HOOK.clear(); }
pub fn register_io_stat(f: IoStatFn)  { let _ = IO_STAT_HOOK.set(f); }
pub fn register_io_revoke(f: IoRevokeFn) { let _ = IO_REVOKE_HOOK.set(f); }
pub fn register_trivfs_modify_stat(f: TrivfsModifyStatFn) {
    let _ = MODIFY_STAT_HOOK.set(f);
}
pub fn register_trivfs_goaway(f: TrivfsGoawayFn) { let _ = GOAWAY_HOOK.set(f); }

// ── linker-visible symbols ──

#[unsafe(no_mangle)]
pub unsafe extern "C-unwind" fn trivfs_S_io_write(
    io_object: *mut trivfs_protid_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
    data: const_data_t,
    dataCnt: mach_msg_type_number_t,
    offset: loff_t,
    amount: *mut vm_size_t,
) -> kern_return_t {
    match IO_WRITE_HOOK.get() {
        Some(f) => f(io_object, reply, replyPoly, data, dataCnt, offset, amount),
        None => {
            // Faithful to C (io-write.c:32): if the translator does not allow
            // writes, EBADF; if it did not register io_write, EOPNOTSUPP.
            if allow_open() & O_WRITE as c_int == 0 {
                EBADF
            } else {
                EOPNOTSUPP
            }
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C-unwind" fn trivfs_S_io_read(
    io_object: *mut trivfs_protid_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
    data: *mut data_t,
    dataCnt: *mut mach_msg_type_number_t,
    offset: loff_t,
    amount: vm_size_t,
) -> kern_return_t {
    match IO_READ_HOOK.get() {
        Some(f) => f(io_object, reply, replyPoly, data, dataCnt, offset, amount),
        None => EOPNOTSUPP,
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C-unwind" fn trivfs_S_io_stat(
    stat_object: *mut trivfs_protid_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
    stat_info: *mut io_statbuf_t,
) -> kern_return_t {
    match IO_STAT_HOOK.get() {
        Some(f) => f(stat_object, reply, replyPoly, stat_info),
        None => {
            if stat_object.is_null() {
                return EOPNOTSUPP;
            }
            let cred = unsafe { &*stat_object };
            let err = unsafe { times::io_stat(cred.realnode, stat_info) };
            if err == 0 {
                let fsid_val = fsid();                 // atomic fetch_update (lazy-init included)
                (*stat_info).st_fstype = fstype() as u32;
                (*stat_info).st_fsid = fsid_val as u64;
                (*stat_info).st_mode =
                    ((*stat_info).st_mode & !S_IFMT & !S_ITRANS) | S_IFCHR | S_IROOT;
                trivfs_modify_stat(stat_object, stat_info);
            }
            err
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C-unwind" fn trivfs_S_io_revoke(
    cred: *mut trivfs_protid_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
) -> kern_return_t {
    match IO_REVOKE_HOOK.get() {
        Some(f) => f(cred, reply, replyPoly),
        None => {
            if cred.is_null() { EOPNOTSUPP }
            else { unsafe { io_revoke((*cred).realnode) } }
        },
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn trivfs_modify_stat(cred: *mut trivfs_protid_t, st: *mut io_statbuf_t) {
    if let Some(f) = MODIFY_STAT_HOOK.get() {
        f(cred, st);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn trivfs_goaway(cntl: *mut trivfs_control_t, flags: c_int) -> mach_error_t {
    if let Some(f) = GOAWAY_HOOK.get() { unsafe{ f(cntl, flags) } } else { std::process::exit(0) }
}

// -- Consts --

const S_IFMT: u32 = 0o170000;
const S_IFCHR: u32 = 0o020000;
const S_ITRANS: u32 = 0o070000000;
const S_IROOT: u32 = 0o040000000;