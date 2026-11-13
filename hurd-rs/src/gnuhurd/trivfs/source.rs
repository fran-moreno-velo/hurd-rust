use crate::gnumach::error::mach_error_t;
use crate::gnumach::port::mach_port_t;
use crate::gnumach::message::mach_msg_type_name_t;
use crate::gnumach::error::EOPNOTSUPP;
use crate::gnuhurd::trivfs::types::trivfs_control_t;
use crate::debug;
use crate::gnuhurd::trivfs::hooks::Hook;

use std::ffi::c_char;

pub type GetSourceFn = unsafe extern "C-unwind" fn(
    source: *mut c_char,
    source_len: usize,
) -> mach_error_t;

static GET_SOURCE_HOOK: Hook<GetSourceFn> = Hook::new();

pub fn register_get_source(f: GetSourceFn) {
    let _ = GET_SOURCE_HOOK.set(f);
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn trivfs_get_source(
    source: *mut c_char,
    source_len: usize,
) -> mach_error_t {
    let hook = GET_SOURCE_HOOK.get();
    let ret = match hook {
        Some(f) => f(source, source_len),
        None => EOPNOTSUPP,
    };
    debug!("[DEBUG] trivfs_get_source: hook={:?} ret={}", hook, ret);
    ret
}

#[unsafe(no_mangle)]
pub unsafe extern "C-unwind" fn trivfs_S_fsys_get_source(
    server: *mut trivfs_control_t,
    _reply: mach_port_t,
    _replyPoly: mach_msg_type_name_t,
    source: *mut c_char,
) -> mach_error_t {
    // #16: 1024 == size_of of the _Xfsys_get_source reply buffer
    // (fsys_server.rs Reply_get_source.source: [c_char; 1024]); the hook gets
    // source_len and is responsible for not writing past it.
    let ret = if server.is_null() { EOPNOTSUPP } else { trivfs_get_source(source, 1024) };
    debug!("[DEBUG] trivfs_S_fsys_get_source: server={:p} ret={}", server, ret);
    ret
}