//===========================================================================//
// crate::gnuhurd::trivfs::fsys_stubs                                        //
//---------------------------------------------------------------------------//
// From /hurd/libtrivfs/fsys-stubs.c                                         //
// Handlers trivfs_S_fsys_* whose C default is a plain EOPNOTSUPP (weak       //
// symbol meant to be overridden by the translator). Ported to Rust with the  //
// Hook pattern: register_* lets each translator provide its own              //
// implementation; without a hook the default returns EOPNOTSUPP, matching    //
// the C behaviour.                                                          //
//===========================================================================//

#![allow(unsafe_op_in_unsafe_fn, dead_code)]

use std::ffi::{c_char, c_int, c_void};

use libc::uid_t;

use crate::gnumach::kern_return::kern_return_t;
use crate::gnumach::message::{
    mach_msg_type_name_t, mach_msg_type_number_t, MACH_MSG_TYPE_MAKE_SEND,
};
use crate::gnumach::port::{mach_port_t, mach_port_deallocate};
use crate::gnumach::task::mach_task_self;
use crate::gnumach::error::{EOPNOTSUPP, EROFS, EACCES, EAGAIN};
use crate::gnuhurd::io::{
    data_t, portarray_t, iohelp_return_malloced_buffer, iohelp_create_complex_iouser, iouser,
};
use crate::gnuhurd::trivfs::hooks::{
    Hook, load_getroot, load_check_access, load_check_open, load_open,
};
use crate::gnuhurd::trivfs::types::trivfs_control_t;
use crate::gnuhurd::trivfs::append::{trivfs_append_args, vec_to_argz};
use crate::gnuhurd::trivfs::open::trivfs_open;
use crate::gnuhurd::trivfs::private::_is_privileged;
use crate::gnuhurd::ports::{ports_get_right, ports_port_deref};
use crate::gnuhurd::fcntl::{O_CREAT, O_EXCL, O_EXEC, O_HURD, O_NOLINK, O_NOTRANS, O_READ, O_WRITE};
use crate::gnuhurd::types::FS_RETRY_NORMAL;
use crate::gnuhurd::mig_user::{io_duplicate, io_restrict_auth};
use crate::gnuhurd::trivfs::symbols::allow_open;

// ── FsysStartupFn ──
// Note: the first argument is the bootstrap port (mach_port_t), not a control.
pub type FsysStartupFn = unsafe extern "C-unwind" fn(
    bootstrap: mach_port_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
    openflags: c_int,
    control_port: mach_port_t,
    realnode: *mut mach_port_t,
    realnodePoly: *mut mach_msg_type_name_t,
) -> kern_return_t;

static FSYS_STARTUP_HOOK: Hook<FsysStartupFn> = Hook::new();
pub fn register_fsys_startup(f: FsysStartupFn) { let _ = FSYS_STARTUP_HOOK.set(f); }

#[unsafe(no_mangle)]
pub unsafe extern "C-unwind" fn trivfs_S_fsys_startup(
    bootstrap: mach_port_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
    openflags: c_int,
    control_port: mach_port_t,
    realnode: *mut mach_port_t,
    realnodePoly: *mut mach_msg_type_name_t,
) -> kern_return_t {
    match FSYS_STARTUP_HOOK.get() {
        Some(f) => f(bootstrap, reply, replyPoly, openflags, control_port, realnode, realnodePoly),
        None => EOPNOTSUPP,
    }
}

// ── FsysGetprivFn ──
pub type FsysGetprivFn = unsafe extern "C-unwind" fn(
    fsys: *mut trivfs_control_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
    host_priv: *mut mach_port_t,
    host_privPoly: *mut mach_msg_type_name_t,
    device_master: *mut mach_port_t,
    device_masterPoly: *mut mach_msg_type_name_t,
    fstask: *mut mach_port_t,
    fstaskPoly: *mut mach_msg_type_name_t,
) -> kern_return_t;

static FSYS_GETPRIV_HOOK: Hook<FsysGetprivFn> = Hook::new();
pub fn register_fsys_getpriv(f: FsysGetprivFn) { let _ = FSYS_GETPRIV_HOOK.set(f); }

#[unsafe(no_mangle)]
pub unsafe extern "C-unwind" fn trivfs_S_fsys_getpriv(
    fsys: *mut trivfs_control_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
    host_priv: *mut mach_port_t,
    host_privPoly: *mut mach_msg_type_name_t,
    device_master: *mut mach_port_t,
    device_masterPoly: *mut mach_msg_type_name_t,
    fstask: *mut mach_port_t,
    fstaskPoly: *mut mach_msg_type_name_t,
) -> kern_return_t {
    match FSYS_GETPRIV_HOOK.get() {
        Some(f) => f(fsys, reply, replyPoly, host_priv, host_privPoly, device_master, device_masterPoly, fstask, fstaskPoly),
        None => EOPNOTSUPP,
    }
}

// ── FsysInitFn ──
pub type FsysInitFn = unsafe extern "C-unwind" fn(
    fsys: *mut trivfs_control_t,
    reply_port: mach_port_t,
    reply_portPoly: mach_msg_type_name_t,
    proc_server: mach_port_t,
    auth_handle: mach_port_t,
) -> kern_return_t;

static FSYS_INIT_HOOK: Hook<FsysInitFn> = Hook::new();
pub fn register_fsys_init(f: FsysInitFn) { let _ = FSYS_INIT_HOOK.set(f); }

#[unsafe(no_mangle)]
pub unsafe extern "C-unwind" fn trivfs_S_fsys_init(
    fsys: *mut trivfs_control_t,
    reply_port: mach_port_t,
    reply_portPoly: mach_msg_type_name_t,
    proc_server: mach_port_t,
    auth_handle: mach_port_t,
) -> kern_return_t {
    match FSYS_INIT_HOOK.get() {
        Some(f) => f(fsys, reply_port, reply_portPoly, proc_server, auth_handle),
        None => EOPNOTSUPP,
    }
}

// ── FsysGetfileFn ──
pub type FsysGetfileFn = unsafe extern "C-unwind" fn(
    fsys: *mut trivfs_control_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
    gen_uids: *const uid_t,
    gen_uidsCnt: mach_msg_type_number_t,
    gen_gids: *const uid_t,
    gen_gidsCnt: mach_msg_type_number_t,
    filehandle: *const c_char,
    filehandleCnt: mach_msg_type_number_t,
    file: *mut mach_port_t,
    filePoly: *mut mach_msg_type_name_t,
) -> kern_return_t;

static FSYS_GETFILE_HOOK: Hook<FsysGetfileFn> = Hook::new();
pub fn register_fsys_getfile(f: FsysGetfileFn) { let _ = FSYS_GETFILE_HOOK.set(f); }

#[unsafe(no_mangle)]
pub unsafe extern "C-unwind" fn trivfs_S_fsys_getfile(
    fsys: *mut trivfs_control_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
    gen_uids: *const uid_t,
    gen_uidsCnt: mach_msg_type_number_t,
    gen_gids: *const uid_t,
    gen_gidsCnt: mach_msg_type_number_t,
    filehandle: *const c_char,
    filehandleCnt: mach_msg_type_number_t,
    file: *mut mach_port_t,
    filePoly: *mut mach_msg_type_name_t,
) -> kern_return_t {
    match FSYS_GETFILE_HOOK.get() {
        Some(f) => f(fsys, reply, replyPoly, gen_uids, gen_uidsCnt, gen_gids, gen_gidsCnt, filehandle, filehandleCnt, file, filePoly),
        None => EOPNOTSUPP,
    }
}

// ── FsysForwardFn ──
// Note: the first argument is a port (mach_port_t), not a control.
pub type FsysForwardFn = unsafe extern "C-unwind" fn(
    server: mach_port_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
    requestor: mach_port_t,
    argv: *const c_char,
    argvCnt: mach_msg_type_number_t,
) -> kern_return_t;

static FSYS_FORWARD_HOOK: Hook<FsysForwardFn> = Hook::new();
pub fn register_fsys_forward(f: FsysForwardFn) { let _ = FSYS_FORWARD_HOOK.set(f); }

#[unsafe(no_mangle)]
pub unsafe extern "C-unwind" fn trivfs_S_fsys_forward(
    server: mach_port_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
    requestor: mach_port_t,
    argv: *const c_char,
    argvCnt: mach_msg_type_number_t,
) -> kern_return_t {
    match FSYS_FORWARD_HOOK.get() {
        Some(f) => f(server, reply, replyPoly, requestor, argv, argvCnt),
        None => EOPNOTSUPP,
    }
}

// ── FsysGetChildrenFn ──
pub type FsysGetChildrenFn = unsafe extern "C-unwind" fn(
    server: *mut trivfs_control_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
    names: *mut data_t,
    namesCnt: *mut mach_msg_type_number_t,
    controls: *mut portarray_t,
    controlsPoly: *mut mach_msg_type_name_t,
    controlsCnt: *mut mach_msg_type_number_t,
) -> kern_return_t;

static FSYS_GET_CHILDREN_HOOK: Hook<FsysGetChildrenFn> = Hook::new();
pub fn register_fsys_get_children(f: FsysGetChildrenFn) { let _ = FSYS_GET_CHILDREN_HOOK.set(f); }

#[unsafe(no_mangle)]
pub unsafe extern "C-unwind" fn trivfs_S_fsys_get_children(
    server: *mut trivfs_control_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
    names: *mut data_t,
    namesCnt: *mut mach_msg_type_number_t,
    controls: *mut portarray_t,
    controlsPoly: *mut mach_msg_type_name_t,
    controlsCnt: *mut mach_msg_type_number_t,
) -> kern_return_t {
    match FSYS_GET_CHILDREN_HOOK.get() {
        Some(f) => f(server, reply, replyPoly, names, namesCnt, controls, controlsPoly, controlsCnt),
        None => EOPNOTSUPP,
    }
}

// ── FsysSyncfsFn ──
pub type FsysSyncfsFn = unsafe extern "C-unwind" fn(
    cntl: *mut trivfs_control_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
    wait: c_int,
    do_children: c_int,
) -> kern_return_t;

static FSYS_SYNCFS_HOOK: Hook<FsysSyncfsFn> = Hook::new();
pub fn register_fsys_syncfs(f: FsysSyncfsFn) { let _ = FSYS_SYNCFS_HOOK.set(f); }

#[unsafe(no_mangle)]
pub unsafe extern "C-unwind" fn trivfs_S_fsys_syncfs(
    cntl: *mut trivfs_control_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
    wait: c_int,
    do_children: c_int,
) -> kern_return_t {
    match FSYS_SYNCFS_HOOK.get() {
        Some(f) => f(cntl, reply, replyPoly, wait, do_children),
        None => if cntl.is_null() { EOPNOTSUPP } else {
            crate::gnuhurd::mig_user::file_sync((*cntl).underlying, wait, 0)
        },
    }
}

// ── FsysGetOptionsFn ──
pub type FsysGetOptionsFn = unsafe extern "C-unwind" fn(
    fsys: *mut trivfs_control_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
    data: *mut data_t,
    len: *mut mach_msg_type_number_t,
) -> kern_return_t;

static FSYS_GET_OPTIONS_HOOK: Hook<FsysGetOptionsFn> = Hook::new();
pub fn register_fsys_get_options(f: FsysGetOptionsFn) { let _ = FSYS_GET_OPTIONS_HOOK.set(f); }

#[unsafe(no_mangle)]
pub unsafe extern "C-unwind" fn trivfs_S_fsys_get_options(
    fsys: *mut trivfs_control_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
    data: *mut data_t,
    len: *mut mach_msg_type_number_t,
) -> kern_return_t {
    match FSYS_GET_OPTIONS_HOOK.get() {
        Some(f) => f(fsys, reply, replyPoly, data, len),
        None => {
            if fsys.is_null() { return EOPNOTSUPP; }
            let mut argz: *mut c_char = std::ptr::null_mut();
            let mut argz_len: usize = 0;
            // argz_add(&argz, &argz_len, program_invocation_name)
            let name = unsafe { std::ffi::CStr::from_ptr(program_invocation_name) }
                .to_str().unwrap_or("");
            let mut err = unsafe { vec_to_argz(&mut argz, &mut argz_len, name) };
            if err != 0 { return err; }
            err = unsafe { trivfs_append_args(fsys, &mut argz, &mut argz_len) };
            if err != 0 {
                unsafe { libc::free(argz as *mut c_void); }
                return err;
            }
            err = unsafe { iohelp_return_malloced_buffer(argz, argz_len, data, len) };
            err
        },
    }
}

unsafe extern "C" {
    static program_invocation_name: *const c_char;
}

// ── FsysGoawayFn ──
pub type FsysGoawayFn = unsafe extern "C-unwind" fn(
    cred: *mut trivfs_control_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
    flags: c_int,
) -> kern_return_t;

static FSYS_GOAWAY_HOOK: Hook<FsysGoawayFn> = Hook::new();
pub fn register_fsys_goaway(f: FsysGoawayFn) { let _ = FSYS_GOAWAY_HOOK.set(f); }

#[unsafe(no_mangle)]
pub unsafe extern "C-unwind" fn trivfs_S_fsys_goaway(
    cred: *mut trivfs_control_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
    flags: c_int,
) -> kern_return_t {
    match FSYS_GOAWAY_HOOK.get() {
        Some(f) => f(cred, reply, replyPoly, flags),
        None => if cred.is_null() { EOPNOTSUPP } else {
            crate::gnuhurd::trivfs::io_handlers::trivfs_goaway(cred, flags)
        },
    }
}

// ── FsysSetOptionsFn ──
pub type FsysSetOptionsFn = unsafe extern "C-unwind" fn(
    cntl: *mut trivfs_control_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
    data: *const c_char,
    len: mach_msg_type_number_t,
    do_children: c_int,
) -> kern_return_t;

static FSYS_SET_OPTIONS_HOOK: Hook<FsysSetOptionsFn> = Hook::new();
pub fn register_fsys_set_options(f: FsysSetOptionsFn) { let _ = FSYS_SET_OPTIONS_HOOK.set(f); }

#[unsafe(no_mangle)]
pub unsafe extern "C-unwind" fn trivfs_S_fsys_set_options(
    cntl: *mut trivfs_control_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
    data: *const c_char,
    len: mach_msg_type_number_t,
    do_children: c_int,
) -> kern_return_t {
    match FSYS_SET_OPTIONS_HOOK.get() {
        Some(f) => f(cntl, reply, replyPoly, data, len, do_children),
        None => if cntl.is_null() { EOPNOTSUPP } else {
            crate::gnuhurd::trivfs::set_options::trivfs_set_options(cntl, data, len as usize)
        },
    }
}

// ── FsysGetrootFn ──
pub type FsysGetrootFn = unsafe extern "C-unwind" fn(
    fsys: *mut trivfs_control_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
    dotdot: mach_port_t,
    gen_uids: *const uid_t,
    gen_uidsCnt: mach_msg_type_number_t,
    gen_gids: *const uid_t,
    gen_gidsCnt: mach_msg_type_number_t,
    flags: c_int,
    do_retry: *mut crate::gnuhurd::types::retry_type,
    retry_name: *mut c_char,
    file: *mut mach_port_t,
    filePoly: *mut mach_msg_type_name_t,
) -> kern_return_t;

static FSYS_GETROOT_HOOK: Hook<FsysGetrootFn> = Hook::new();
pub fn register_fsys_getroot(f: FsysGetrootFn) { let _ = FSYS_GETROOT_HOOK.set(f); }

#[unsafe(no_mangle)]
pub unsafe extern "C-unwind" fn trivfs_S_fsys_getroot(
    fsys: *mut trivfs_control_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
    dotdot: mach_port_t,
    gen_uids: *const uid_t,
    gen_uidsCnt: mach_msg_type_number_t,
    gen_gids: *const uid_t,
    gen_gidsCnt: mach_msg_type_number_t,
    flags: c_int,
    do_retry: *mut crate::gnuhurd::types::retry_type,
    retry_name: *mut c_char,
    file: *mut mach_port_t,
    filePoly: *mut mach_msg_type_name_t,
) -> kern_return_t {
    match FSYS_GETROOT_HOOK.get() {
        Some(f) => f(fsys, reply, replyPoly, dotdot, gen_uids, gen_uidsCnt, gen_gids, gen_gidsCnt, flags, do_retry, retry_name, file, filePoly),
        None => {
            if fsys.is_null() { return EOPNOTSUPP; }

            if let Some(hook) = load_getroot() {
                let err = unsafe { hook(fsys, reply, replyPoly, dotdot, gen_uids, gen_uidsCnt, gen_gids, gen_gidsCnt, flags, do_retry, retry_name, file, filePoly) };
                if err != EAGAIN { return err; }
            }
            let allow = allow_open();

            // Permission checks on flags.
            if (flags & O_WRITE as c_int & allow) != (flags & O_WRITE as c_int) { return EROFS; }
            if (flags & (O_READ | O_WRITE | O_EXEC) as c_int & allow)
                != (flags & (O_READ | O_WRITE | O_EXEC) as c_int) { return EACCES; }

            // O_CREAT/O_EXCL/O_NOLINK/O_NOTRANS are not meaningful for getroot.
            let mut flags = flags & O_HURD;
            flags &= !(O_CREAT | O_EXCL | O_NOLINK | O_NOTRANS);

            let mut new_realnode: mach_port_t = 0;
            let mut err = {
                // struct idvec { .ids = uids, .num = nuids, .alloced = nuids }
                let mut idv = crate::gnuhurd::io::idvec {
                    ids: gen_uids as *mut uid_t,
                    num: gen_uidsCnt,
                    alloced: gen_uidsCnt,
                };
                if _is_privileged(&mut idv) != 0 {
                    io_duplicate(unsafe { (*fsys).underlying }, &mut new_realnode)
                } else {
                    io_restrict_auth(
                        unsafe { (*fsys).underlying },
                        &mut new_realnode,
                        gen_uids as *const u32, gen_uidsCnt,
                        gen_gids as *const u32, gen_gidsCnt,
                    )
                }
            };
            if err != 0 { return err; }

            let mut user: *mut iouser = std::ptr::null_mut();
            err = unsafe { iohelp_create_complex_iouser(&mut user, gen_uids, gen_uidsCnt, gen_gids, gen_gidsCnt) };
            if err != 0 { return err; }

            // Validate permissions.
            let mut perms: c_int = 0;
            // C ignores file_check_access' return value; only `perms` decides.
            let perr = match load_check_access() {
                Some(f) => unsafe { f(fsys, user, new_realnode, &mut perms) },
                None => unsafe { crate::gnuhurd::mig_user::file_check_access(new_realnode, &mut perms) },
            };
            let _ = perr;
            if (flags & (O_READ | O_WRITE | O_EXEC) as c_int & perms)
                != (flags & (O_READ | O_WRITE | O_EXEC) as c_int) {
                err = EACCES;
            }

            if err == 0 {
                if let Some(hook) = load_check_open() {
                    err = unsafe { hook(fsys, user, flags) };
                }
            }

            let mut cred: *mut crate::gnuhurd::trivfs::types::trivfs_protid_t = std::ptr::null_mut();
            if err == 0 {
                match load_open() {
                    Some(hook) => err = unsafe { hook(fsys, user, dotdot, flags, new_realnode, &mut cred) },
                    None => {
                        err = unsafe { trivfs_open(fsys, user, flags as u32, new_realnode, &mut cred) };
                        if err == 0 {
                            unsafe { mach_port_deallocate(mach_task_self(), dotdot); }
                        }
                    },
                }
            }

            if err != 0 {
                unsafe { mach_port_deallocate(mach_task_self(), new_realnode); }
                unsafe { crate::gnuhurd::io::iohelp_free_iouser(user); }
            } else {
                if !do_retry.is_null() { *do_retry = FS_RETRY_NORMAL; }
                if !retry_name.is_null() { *retry_name = 0; }
                if !file.is_null() { *file = ports_get_right(cred as *mut c_void); }
                if !filePoly.is_null() { *filePoly = MACH_MSG_TYPE_MAKE_SEND; }
                ports_port_deref(cred as *mut c_void);
            }

            err
        },
    }
}
