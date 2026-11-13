//===========================================================================//
// crate::gnuhurd::trivfs::io_stubs                                          //
//---------------------------------------------------------------------------//
// From /hurd/libtrivfs/io-stubs.c                                           //
// Handlers trivfs_S_io_* whose C default is a plain EOPNOTSUPP (weak symbol  //
// meant to be overridden by the translator). Ported to Rust with the Hook    //
// pattern: register_* lets each translator provide its own implementation;   //
// without a hook the default returns EOPNOTSUPP, matching the C behaviour.  //
//===========================================================================//

#![allow(unsafe_op_in_unsafe_fn, dead_code)]

use std::ffi::{c_int, c_uint};

use crate::gnumach::kern_return::kern_return_t;
use crate::gnumach::message::{mach_msg_type_name_t, MACH_MSG_TYPE_MAKE_SEND};
use crate::gnumach::port::{mach_port_t, mach_port_deallocate, MACH_PORT_NULL};
use crate::gnumach::task::mach_task_self;
use crate::gnumach::error::{EOPNOTSUPP, ENOMEM, EINTR};
use crate::gnumach::vm_types::vm_offset_t;
use crate::gnuhurd::trivfs::hooks::Hook;
use crate::gnuhurd::trivfs::types::trivfs_protid_t;
use crate::gnuhurd::io::{iouser, make_idvec, idvec_add, idvec_free, iohelp_create_iouser, iohelp_create_complex_iouser, iohelp_free_iouser, iohelp_reauth};
use crate::gnuhurd::ports::{ports_create_port, ports_create_port_noinstall, ports_get_right, ports_get_send_right, ports_port_deref};
use crate::gnuhurd::trivfs::hooks::load_protid_create;
use crate::gnuhurd::trivfs::private::_is_privileged;

// ── IoAsyncFn ──
pub type IoAsyncFn = unsafe extern "C-unwind" fn(
    io_object: *mut trivfs_protid_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
    notify_port: mach_port_t,
    async_id_port: *mut mach_port_t,
    async_id_portPoly: *mut mach_msg_type_name_t,
) -> kern_return_t;

static IO_ASYNC_HOOK: Hook<IoAsyncFn> = Hook::new();
pub fn register_io_async(f: IoAsyncFn) { let _ = IO_ASYNC_HOOK.set(f); }

#[unsafe(no_mangle)]
pub unsafe extern "C-unwind" fn trivfs_S_io_async(
    io_object: *mut trivfs_protid_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
    notify_port: mach_port_t,
    async_id_port: *mut mach_port_t,
    async_id_portPoly: *mut mach_msg_type_name_t,
) -> kern_return_t {
    match IO_ASYNC_HOOK.get() {
        Some(f) => f(io_object, reply, replyPoly, notify_port, async_id_port, async_id_portPoly),
        None => EOPNOTSUPP,
    }
}

// ── IoModOwnerFn ──
pub type IoModOwnerFn = unsafe extern "C-unwind" fn(
    io_object: *mut trivfs_protid_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
    owner: c_int,
) -> kern_return_t;

static IO_MOD_OWNER_HOOK: Hook<IoModOwnerFn> = Hook::new();
pub fn register_io_mod_owner(f: IoModOwnerFn) { let _ = IO_MOD_OWNER_HOOK.set(f); }

#[unsafe(no_mangle)]
pub unsafe extern "C-unwind" fn trivfs_S_io_mod_owner(
    io_object: *mut trivfs_protid_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
    owner: c_int,
) -> kern_return_t {
    match IO_MOD_OWNER_HOOK.get() {
        Some(f) => f(io_object, reply, replyPoly, owner),
        None => EOPNOTSUPP,
    }
}

// ── IoGetOwnerFn ──
pub type IoGetOwnerFn = unsafe extern "C-unwind" fn(
    io_object: *mut trivfs_protid_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
    owner: *mut c_int,
) -> kern_return_t;

static IO_GET_OWNER_HOOK: Hook<IoGetOwnerFn> = Hook::new();
pub fn register_io_get_owner(f: IoGetOwnerFn) { let _ = IO_GET_OWNER_HOOK.set(f); }

#[unsafe(no_mangle)]
pub unsafe extern "C-unwind" fn trivfs_S_io_get_owner(
    io_object: *mut trivfs_protid_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
    owner: *mut c_int,
) -> kern_return_t {
    match IO_GET_OWNER_HOOK.get() {
        Some(f) => f(io_object, reply, replyPoly, owner),
        None => EOPNOTSUPP,
    }
}

// ── IoGetIckyAsyncIdFn ──
pub type IoGetIckyAsyncIdFn = unsafe extern "C-unwind" fn(
    io_object: *mut trivfs_protid_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
    icky_async_id_port: *mut mach_port_t,
    icky_async_id_portPoly: *mut mach_msg_type_name_t,
) -> kern_return_t;

static IO_GET_ICKY_ASYNC_ID_HOOK: Hook<IoGetIckyAsyncIdFn> = Hook::new();
pub fn register_io_get_icky_async_id(f: IoGetIckyAsyncIdFn) { let _ = IO_GET_ICKY_ASYNC_ID_HOOK.set(f); }

#[unsafe(no_mangle)]
pub unsafe extern "C-unwind" fn trivfs_S_io_get_icky_async_id(
    io_object: *mut trivfs_protid_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
    icky_async_id_port: *mut mach_port_t,
    icky_async_id_portPoly: *mut mach_msg_type_name_t,
) -> kern_return_t {
    match IO_GET_ICKY_ASYNC_ID_HOOK.get() {
        Some(f) => f(io_object, reply, replyPoly, icky_async_id_port, icky_async_id_portPoly),
        None => EOPNOTSUPP,
    }
}

// ── IoMapFn ──
pub type IoMapFn = unsafe extern "C-unwind" fn(
    io_object: *mut trivfs_protid_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
    memobjrd: *mut mach_port_t,
    memobjrdPoly: *mut mach_msg_type_name_t,
    memobjwt: *mut mach_port_t,
    memobjwtPoly: *mut mach_msg_type_name_t,
) -> kern_return_t;

static IO_MAP_HOOK: Hook<IoMapFn> = Hook::new();
pub fn register_io_map(f: IoMapFn) { let _ = IO_MAP_HOOK.set(f); }

#[unsafe(no_mangle)]
pub unsafe extern "C-unwind" fn trivfs_S_io_map(
    io_object: *mut trivfs_protid_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
    memobjrd: *mut mach_port_t,
    memobjrdPoly: *mut mach_msg_type_name_t,
    memobjwt: *mut mach_port_t,
    memobjwtPoly: *mut mach_msg_type_name_t,
) -> kern_return_t {
    match IO_MAP_HOOK.get() {
        Some(f) => f(io_object, reply, replyPoly, memobjrd, memobjrdPoly, memobjwt, memobjwtPoly),
        None => EOPNOTSUPP,
    }
}

// ── IoMapCntlFn ──
pub type IoMapCntlFn = unsafe extern "C-unwind" fn(
    io_object: *mut trivfs_protid_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
    memobj: *mut mach_port_t,
    memobjPoly: *mut mach_msg_type_name_t,
) -> kern_return_t;

static IO_MAP_CNTL_HOOK: Hook<IoMapCntlFn> = Hook::new();
pub fn register_io_map_cntl(f: IoMapCntlFn) { let _ = IO_MAP_CNTL_HOOK.set(f); }

#[unsafe(no_mangle)]
pub unsafe extern "C-unwind" fn trivfs_S_io_map_cntl(
    io_object: *mut trivfs_protid_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
    memobj: *mut mach_port_t,
    memobjPoly: *mut mach_msg_type_name_t,
) -> kern_return_t {
    match IO_MAP_CNTL_HOOK.get() {
        Some(f) => f(io_object, reply, replyPoly, memobj, memobjPoly),
        None => EOPNOTSUPP,
    }
}

// ── IoGetConchFn ──
pub type IoGetConchFn = unsafe extern "C-unwind" fn(
    io_object: *mut trivfs_protid_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
) -> kern_return_t;

static IO_GET_CONCH_HOOK: Hook<IoGetConchFn> = Hook::new();
pub fn register_io_get_conch(f: IoGetConchFn) { let _ = IO_GET_CONCH_HOOK.set(f); }

#[unsafe(no_mangle)]
pub unsafe extern "C-unwind" fn trivfs_S_io_get_conch(
    io_object: *mut trivfs_protid_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
) -> kern_return_t {
    match IO_GET_CONCH_HOOK.get() {
        Some(f) => f(io_object, reply, replyPoly),
        None => EOPNOTSUPP,
    }
}

// ── IoReleaseConchFn ──
pub type IoReleaseConchFn = unsafe extern "C-unwind" fn(
    io_object: *mut trivfs_protid_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
) -> kern_return_t;

static IO_RELEASE_CONCH_HOOK: Hook<IoReleaseConchFn> = Hook::new();
pub fn register_io_release_conch(f: IoReleaseConchFn) { let _ = IO_RELEASE_CONCH_HOOK.set(f); }

#[unsafe(no_mangle)]
pub unsafe extern "C-unwind" fn trivfs_S_io_release_conch(
    io_object: *mut trivfs_protid_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
) -> kern_return_t {
    match IO_RELEASE_CONCH_HOOK.get() {
        Some(f) => f(io_object, reply, replyPoly),
        None => EOPNOTSUPP,
    }
}

// ── IoEofnotifyFn ──
pub type IoEofnotifyFn = unsafe extern "C-unwind" fn(
    io_object: *mut trivfs_protid_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
) -> kern_return_t;

static IO_EOFNOTIFY_HOOK: Hook<IoEofnotifyFn> = Hook::new();
pub fn register_io_eofnotify(f: IoEofnotifyFn) { let _ = IO_EOFNOTIFY_HOOK.set(f); }

#[unsafe(no_mangle)]
pub unsafe extern "C-unwind" fn trivfs_S_io_eofnotify(
    io_object: *mut trivfs_protid_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
) -> kern_return_t {
    match IO_EOFNOTIFY_HOOK.get() {
        Some(f) => f(io_object, reply, replyPoly),
        None => EOPNOTSUPP,
    }
}

// ── IoPrenotifyFn ──
pub type IoPrenotifyFn = unsafe extern "C-unwind" fn(
    io_object: *mut trivfs_protid_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
    write_start: vm_offset_t,
    write_end: vm_offset_t,
) -> kern_return_t;

static IO_PRENOTIFY_HOOK: Hook<IoPrenotifyFn> = Hook::new();
pub fn register_io_prenotify(f: IoPrenotifyFn) { let _ = IO_PRENOTIFY_HOOK.set(f); }

#[unsafe(no_mangle)]
pub unsafe extern "C-unwind" fn trivfs_S_io_prenotify(
    io_object: *mut trivfs_protid_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
    write_start: vm_offset_t,
    write_end: vm_offset_t,
) -> kern_return_t {
    match IO_PRENOTIFY_HOOK.get() {
        Some(f) => f(io_object, reply, replyPoly, write_start, write_end),
        None => EOPNOTSUPP,
    }
}

// ── IoPostnotifyFn ──
pub type IoPostnotifyFn = unsafe extern "C-unwind" fn(
    io_object: *mut trivfs_protid_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
    write_start: vm_offset_t,
    write_end: vm_offset_t,
) -> kern_return_t;

static IO_POSTNOTIFY_HOOK: Hook<IoPostnotifyFn> = Hook::new();
pub fn register_io_postnotify(f: IoPostnotifyFn) { let _ = IO_POSTNOTIFY_HOOK.set(f); }

#[unsafe(no_mangle)]
pub unsafe extern "C-unwind" fn trivfs_S_io_postnotify(
    io_object: *mut trivfs_protid_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
    write_start: vm_offset_t,
    write_end: vm_offset_t,
) -> kern_return_t {
    match IO_POSTNOTIFY_HOOK.get() {
        Some(f) => f(io_object, reply, replyPoly, write_start, write_end),
        None => EOPNOTSUPP,
    }
}

// ── IoReadnotifyFn ──
pub type IoReadnotifyFn = unsafe extern "C-unwind" fn(
    io_object: *mut trivfs_protid_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
) -> kern_return_t;

static IO_READNOTIFY_HOOK: Hook<IoReadnotifyFn> = Hook::new();
pub fn register_io_readnotify(f: IoReadnotifyFn) { let _ = IO_READNOTIFY_HOOK.set(f); }

#[unsafe(no_mangle)]
pub unsafe extern "C-unwind" fn trivfs_S_io_readnotify(
    io_object: *mut trivfs_protid_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
) -> kern_return_t {
    match IO_READNOTIFY_HOOK.get() {
        Some(f) => f(io_object, reply, replyPoly),
        None => EOPNOTSUPP,
    }
}

// ── IoReadsleepFn ──
pub type IoReadsleepFn = unsafe extern "C-unwind" fn(
    io_object: *mut trivfs_protid_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
) -> kern_return_t;

static IO_READSLEEP_HOOK: Hook<IoReadsleepFn> = Hook::new();
pub fn register_io_readsleep(f: IoReadsleepFn) { let _ = IO_READSLEEP_HOOK.set(f); }

#[unsafe(no_mangle)]
pub unsafe extern "C-unwind" fn trivfs_S_io_readsleep(
    io_object: *mut trivfs_protid_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
) -> kern_return_t {
    match IO_READSLEEP_HOOK.get() {
        Some(f) => f(io_object, reply, replyPoly),
        None => EOPNOTSUPP,
    }
}

// ── IoSigioFn ──
pub type IoSigioFn = unsafe extern "C-unwind" fn(
    io_object: *mut trivfs_protid_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
) -> kern_return_t;

static IO_SIGIO_HOOK: Hook<IoSigioFn> = Hook::new();
pub fn register_io_sigio(f: IoSigioFn) { let _ = IO_SIGIO_HOOK.set(f); }

#[unsafe(no_mangle)]
pub unsafe extern "C-unwind" fn trivfs_S_io_sigio(
    io_object: *mut trivfs_protid_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
) -> kern_return_t {
    match IO_SIGIO_HOOK.get() {
        Some(f) => f(io_object, reply, replyPoly),
        None => EOPNOTSUPP,
    }
}

// ── IoPathconfFn ──
pub type IoPathconfFn = unsafe extern "C-unwind" fn(
    io_object: *mut trivfs_protid_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
    name: c_int,
    value: *mut c_int,
) -> kern_return_t;

static IO_PATHCONF_HOOK: Hook<IoPathconfFn> = Hook::new();
pub fn register_io_pathconf(f: IoPathconfFn) { let _ = IO_PATHCONF_HOOK.set(f); }

#[unsafe(no_mangle)]
pub unsafe extern "C-unwind" fn trivfs_S_io_pathconf(
    io_object: *mut trivfs_protid_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
    name: c_int,
    value: *mut c_int,
) -> kern_return_t {
    match IO_PATHCONF_HOOK.get() {
        Some(f) => f(io_object, reply, replyPoly, name, value),
        None => if io_object.is_null() { EOPNOTSUPP } else {
            crate::gnuhurd::mig_user::io_pathconf((*io_object).realnode, name, value)
        },
    }
}

// ── IoDuplicateFn ──
pub type IoDuplicateFn = unsafe extern "C-unwind" fn(
    io_object: *mut trivfs_protid_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
    newport: *mut mach_port_t,
    newportPoly: *mut mach_msg_type_name_t,
) -> kern_return_t;

static IO_DUPLICATE_HOOK: Hook<IoDuplicateFn> = Hook::new();
pub fn register_io_duplicate(f: IoDuplicateFn) { let _ = IO_DUPLICATE_HOOK.set(f); }

#[unsafe(no_mangle)]
pub unsafe extern "C-unwind" fn trivfs_S_io_duplicate(
    io_object: *mut trivfs_protid_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
    newport: *mut mach_port_t,
    newportPoly: *mut mach_msg_type_name_t,
) -> kern_return_t {
    match IO_DUPLICATE_HOOK.get() {
        Some(f) => f(io_object, reply, replyPoly, newport, newportPoly),
        None => {
            if io_object.is_null() { return EOPNOTSUPP; }
            let mut newcred: *mut trivfs_protid_t = std::ptr::null_mut();
            let err = crate::gnuhurd::trivfs::protid::trivfs_protid_dup(io_object, &mut newcred);
            if err != 0 {
                return err;
            }
            if !newport.is_null() { *newport = crate::gnuhurd::ports::ports_get_right(newcred as *mut std::ffi::c_void); }
            if !newportPoly.is_null() { *newportPoly = crate::gnumach::message::MACH_MSG_TYPE_MAKE_SEND; }
            crate::gnuhurd::ports::ports_port_deref(newcred as *mut std::ffi::c_void);
            0
        },
    }
}

// ── IoIdentityFn ──
pub type IoIdentityFn = unsafe extern "C-unwind" fn(
    io_object: *mut trivfs_protid_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
    idport: *mut mach_port_t,
    idportPoly: *mut mach_msg_type_name_t,
    fsidport: *mut mach_port_t,
    fsidportPoly: *mut mach_msg_type_name_t,
    fileno: *mut u64,
) -> kern_return_t;

static IO_IDENTITY_HOOK: Hook<IoIdentityFn> = Hook::new();
pub fn register_io_identity(f: IoIdentityFn) { let _ = IO_IDENTITY_HOOK.set(f); }

#[unsafe(no_mangle)]
pub unsafe extern "C-unwind" fn trivfs_S_io_identity(
    io_object: *mut trivfs_protid_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
    idport: *mut mach_port_t,
    idportPoly: *mut mach_msg_type_name_t,
    fsidport: *mut mach_port_t,
    fsidportPoly: *mut mach_msg_type_name_t,
    fileno: *mut u64,
) -> kern_return_t {
    match IO_IDENTITY_HOOK.get() {
        Some(f) => f(io_object, reply, replyPoly, idport, idportPoly, fsidport, fsidportPoly, fileno),
        None => {
            if io_object.is_null() { return EOPNOTSUPP; }
            let mut st: crate::gnuhurd::io::io_statbuf_t = std::mem::zeroed();
            let cred = unsafe { &*io_object };
            let err = unsafe { crate::gnuhurd::mig_user::io_stat(cred.realnode, &mut st) };
            if err != 0 { return err; }
            crate::gnuhurd::trivfs::io_handlers::trivfs_modify_stat(io_object, &mut st);
            let cntl = match cred.po_ref() { Ok(p) => p.cntl, Err(e) => return e };
            if !idport.is_null() { *idport = unsafe { (*cntl).file_id }; }
            if !idportPoly.is_null() { *idportPoly = MACH_MSG_TYPE_MAKE_SEND; }
            if !fsidport.is_null() { *fsidport = unsafe { (*cntl).filesys_id }; }
            if !fsidportPoly.is_null() { *fsidportPoly = MACH_MSG_TYPE_MAKE_SEND; }
            if !fileno.is_null() { *fileno = st.st_ino; }
            0
        },
    }
}

// ── IoServerVersionFn ──
pub type IoServerVersionFn = unsafe extern "C-unwind" fn(
    io_object: *mut trivfs_protid_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
    server_name: *mut std::ffi::c_char,
    server_major_version: *mut c_int,
    server_minor_version: *mut c_int,
    server_edit_level: *mut c_int,
) -> kern_return_t;

static IO_SERVER_VERSION_HOOK: Hook<IoServerVersionFn> = Hook::new();
pub fn register_io_server_version(f: IoServerVersionFn) { let _ = IO_SERVER_VERSION_HOOK.set(f); }

// trivfs_server_name/version are weak symbols in C (trivfs.h:79,83): each
// translator may define them. Instead of relying on weak externs (unstable),
// the default returns EOPNOTSUPP; translators that want to report a version
// register the hook via register_io_server_version().

#[unsafe(no_mangle)]
pub unsafe extern "C-unwind" fn trivfs_S_io_server_version(
    io_object: *mut trivfs_protid_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
    server_name: *mut std::ffi::c_char,
    server_major_version: *mut c_int,
    server_minor_version: *mut c_int,
    server_edit_level: *mut c_int,
) -> kern_return_t {
    match IO_SERVER_VERSION_HOOK.get() {
        Some(f) => f(io_object, reply, replyPoly, server_name, server_major_version, server_minor_version, server_edit_level),
        None => {
            if io_object.is_null() { return EOPNOTSUPP; }
            EOPNOTSUPP
        },
    }
}

// ── IoRestrictAuthFn ──
pub type IoRestrictAuthFn = unsafe extern "C-unwind" fn(
    io_object: *mut trivfs_protid_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
    new_object: *mut mach_port_t,
    new_objectPoly: *mut mach_msg_type_name_t,
    uids: *const c_uint,
    uidsCnt: u32,
    gids: *const c_uint,
    gidsCnt: u32,
) -> kern_return_t;

static IO_RESTRICT_AUTH_HOOK: Hook<IoRestrictAuthFn> = Hook::new();
pub fn register_io_restrict_auth(f: IoRestrictAuthFn) { let _ = IO_RESTRICT_AUTH_HOOK.set(f); }

/// listmember: 1 if LIST[0..n) contains QUERY.
unsafe fn listmember(list: *const u32, query: u32, n: u32) -> bool {
    if list.is_null() { return false; }
    for i in 0..n as usize {
        if *list.add(i) == query { return true; }
    }
    false
}

#[unsafe(no_mangle)]
pub unsafe extern "C-unwind" fn trivfs_S_io_restrict_auth(
    io_object: *mut trivfs_protid_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
    new_object: *mut mach_port_t,
    new_objectPoly: *mut mach_msg_type_name_t,
    uids: *const c_uint,
    uidsCnt: u32,
    gids: *const c_uint,
    gidsCnt: u32,
) -> kern_return_t {
    match IO_RESTRICT_AUTH_HOOK.get() {
        Some(f) => f(io_object, reply, replyPoly, new_object, new_objectPoly, uids, uidsCnt, gids, gidsCnt),
        None => {
            if io_object.is_null() { return EOPNOTSUPP; }
            let cred = unsafe { &*io_object };
            let user: *mut iouser;

            if cred.isroot != 0 {
                // CRED has root access: may use any ids.
                let mut u: *mut iouser = std::ptr::null_mut();
                let err = unsafe { iohelp_create_complex_iouser(&mut u, uids as *const u32, uidsCnt, gids as *const u32, gidsCnt) };
                if err != 0 { return err; }
                user = u;
            } else {
                // Use any of the requested ids that CRED already has.
                let uvec = unsafe { make_idvec() };
                if uvec.is_null() { return ENOMEM; }
                let gvec = unsafe { make_idvec() };
                if gvec.is_null() { unsafe { idvec_free(uvec); } return ENOMEM; }

                let mut err: kern_return_t = 0;
                let uidids = unsafe { (*cred.user).uids };
                for i in 0..unsafe { (*uidids).num } as usize {
                    let q = unsafe { *(*uidids).ids.add(i) };
                    if unsafe { listmember(uids, q, uidsCnt) } {
                        err = unsafe { idvec_add(uvec, q) };
                        if err != 0 { break; }
                    }
                }
                if err == 0 {
                    let gidids = unsafe { (*cred.user).gids };
                    for i in 0..unsafe { (*gidids).num } as usize {
                        let q = unsafe { *(*gidids).ids.add(i) };
                        if unsafe { listmember(gids, q, gidsCnt) } {
                            err = unsafe { idvec_add(gvec, q) };
                            if err != 0 { break; }
                        }
                    }
                }
                if err != 0 {
                    unsafe { idvec_free(uvec); }
                    unsafe { idvec_free(gvec); }
                    return err;
                }
                let mut u: *mut iouser = std::ptr::null_mut();
                err = unsafe { iohelp_create_iouser(&mut u, uvec, gvec) };
                if err != 0 {
                    unsafe { idvec_free(uvec); }
                    unsafe { idvec_free(gvec); }
                    return err;
                }
                user = u;
            }

            let cntl = match cred.po_ref() { Ok(p) => p.cntl, Err(e) => { unsafe { iohelp_free_iouser(user); } return e; } };
            let mut newcred: *mut trivfs_protid_t = std::ptr::null_mut();
            let mut err = unsafe {
                ports_create_port(
                    (*cntl).protid_class,
                    (*cntl).protid_bucket,
                    std::mem::size_of::<trivfs_protid_t>(),
                    (&mut newcred) as *mut *mut trivfs_protid_t as *mut std::ffi::c_void,
                )
            };
            if err != 0 {
                unsafe { iohelp_free_iouser(user); }
                return err;
            }

            let nc = unsafe { &mut *newcred };
            nc.po = cred.po;
            if let Ok(p) = nc.po_ref_mut() { p.ref_inc(); }
            nc.user = user;
            nc.isroot = if cred.isroot != 0 {
                unsafe { _is_privileged((*user).uids) }
            } else { 0 };
            nc.hook = cred.hook;

            err = unsafe {
                crate::gnuhurd::mig_user::io_restrict_auth(
                    cred.realnode,
                    &mut nc.realnode,
                    (*(*user).uids).ids as *const u32, (*(*user).uids).num,
                    (*(*user).gids).ids as *const u32, (*(*user).gids).num,
                )
            };
            if err == 0 {
                if let Some(hook) = load_protid_create() {
                    err = unsafe { hook(newcred) };
                    if err != 0 {
                        unsafe { mach_port_deallocate(mach_task_self(), nc.realnode); }
                    }
                }
            }

            if err != 0 {
                nc.realnode = MACH_PORT_NULL;
            } else {
                if !new_object.is_null() { *new_object = ports_get_right(newcred as *mut std::ffi::c_void); }
                if !new_objectPoly.is_null() { *new_objectPoly = MACH_MSG_TYPE_MAKE_SEND; }
            }

            ports_port_deref(newcred as *mut std::ffi::c_void);
            0
        },
    }
}

// ── IoReauthenticateFn ──
pub type IoReauthenticateFn = unsafe extern "C-unwind" fn(
    io_object: *mut trivfs_protid_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
    rendezvous2: mach_port_t,
) -> kern_return_t;

static IO_REAUTHENTICATE_HOOK: Hook<IoReauthenticateFn> = Hook::new();
pub fn register_io_reauthenticate(f: IoReauthenticateFn) { let _ = IO_REAUTHENTICATE_HOOK.set(f); }

unsafe extern "C" {
    /// getauth (libc, <hurd/auth.h>): return the process auth port.
    fn getauth() -> mach_port_t;
    /// mach_port_move_member (mach/mach_port.h).
    fn mach_port_move_member(task: mach_port_t, member: mach_port_t, set: mach_port_t) -> kern_return_t;
}

#[unsafe(no_mangle)]
pub unsafe extern "C-unwind" fn trivfs_S_io_reauthenticate(
    io_object: *mut trivfs_protid_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
    rendezvous2: mach_port_t,
) -> kern_return_t {
    match IO_REAUTHENTICATE_HOOK.get() {
        Some(f) => f(io_object, reply, replyPoly, rendezvous2),
        None => {
            if io_object.is_null() { return EOPNOTSUPP; }
            let cred = unsafe { &*io_object };
            let cntl = match cred.po_ref() { Ok(p) => p.cntl, Err(e) => return e };

            let mut newcred: *mut trivfs_protid_t = std::ptr::null_mut();
            let mut err: kern_return_t;
            loop {
                err = unsafe {
                    ports_create_port_noinstall(
                        (*cntl).protid_class,
                        (*cntl).protid_bucket,
                        std::mem::size_of::<trivfs_protid_t>(),
                        (&mut newcred) as *mut *mut trivfs_protid_t as *mut std::ffi::c_void,
                    )
                };
                if err != EINTR { break; }
            }
            if err != 0 { return err; }

            let auth = unsafe { getauth() };
            let newright = unsafe { ports_get_send_right(newcred as *mut std::ffi::c_void) };
            debug_assert!(newright != MACH_PORT_NULL);

            let nc = unsafe { &mut *newcred };
            err = unsafe { iohelp_reauth(&mut nc.user, auth, rendezvous2, newright, 1) };
            if err == 0 {
                unsafe { mach_port_deallocate(mach_task_self(), rendezvous2); }
            }
            unsafe { mach_port_deallocate(mach_task_self(), auth); }
            if err != 0 { return err; }

            unsafe { mach_port_deallocate(mach_task_self(), newright); }

            nc.isroot = unsafe { _is_privileged((*nc.user).uids) };
            nc.hook = cred.hook;
            nc.po = cred.po;
            if let Ok(p) = nc.po_ref_mut() { p.ref_inc(); }

            loop {
                err = unsafe {
                    crate::gnuhurd::mig_user::io_restrict_auth(
                        (*cntl).underlying,
                        &mut nc.realnode,
                        (*(*nc.user).uids).ids as *const u32, (*(*nc.user).uids).num,
                        (*(*nc.user).gids).ids as *const u32, (*(*nc.user).gids).num,
                    )
                };
                if err != EINTR { break; }
            }

            if err == 0 {
                if let Some(hook) = load_protid_create() {
                    // Faithful to C (io-reauthenticate.c:74-79): retry
                    // EINTR around the hook.
                    loop {
                        err = unsafe { hook(newcred) };
                        if err != EINTR { break; }
                    }
                    if err != 0 {
                        unsafe { mach_port_deallocate(mach_task_self(), nc.realnode); }
                    }
                }
            }

            if err != 0 {
                nc.realnode = MACH_PORT_NULL;
            }

            // Move the new port into the same portset as the bucket.
            match unsafe { (*cntl).protid_bucket.as_ref() } {
                Some(bucket) => unsafe {
                    mach_port_move_member(mach_task_self(), nc.pi.port_right, bucket.portset);
                },
                None => {
                    ports_port_deref(newcred as *mut std::ffi::c_void);
                    return EOPNOTSUPP as kern_return_t;
                }
            }

            ports_port_deref(newcred as *mut std::ffi::c_void);
            err
        },
    }
}
