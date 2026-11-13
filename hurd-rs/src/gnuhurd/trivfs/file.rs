use std::ffi::{c_char, c_int, c_uint, c_void};
use crate::gnuhurd::trivfs::hooks::Hook;
use crate::gnumach::kern_return::kern_return_t;
use crate::gnumach::port::{mach_port_name_t, mach_port_t};
use crate::gnumach::message::mach_msg_type_name_t;
use crate::gnumach::error::{EOPNOTSUPP, EMIG_BAD_ID, ENULLPTR, EPERM};
use crate::gnuhurd::trivfs::types::trivfs_protid_t;
use crate::gnuhurd::io::{loff_t, data_t, portarray_t, intarray_t, off_array_t, iohelp_return_malloced_buffer};
use crate::gnumach::message::mach_msg_type_number_t;
use crate::gnuhurd::io::fsys_statfsbuf_t;
use crate::gnuhurd::trivfs::times;
use crate::gnuhurd::ports::ports_get_right;
use crate::gnumach::task::mach_task_self;
use crate::gnumach::port::mach_port_deallocate;
use crate::gnumach::message::MACH_MSG_TYPE_MAKE_SEND;
use crate::gnumach::message::MACH_MSG_TYPE_COPY_SEND;
use crate::gnuhurd::trivfs::append::{trivfs_append_args, vec_to_argz};
use crate::gnuhurd::trivfs::io_stubs::trivfs_S_io_duplicate;
use crate::gnuhurd::trivfs::symbols::{fsid, fstype};

/// flock_t (fs.defs): 4×7 bytes on the wire. C: _Static_assert(sizeof==4*7).
pub type flock_t = [u32; 7];

// ── FileSyncFn ──
pub type FileSyncFn = unsafe extern "C-unwind" fn(
    cred: *mut trivfs_protid_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
    wait: c_int,
    omitmeta: c_int,
) -> kern_return_t;

static FILE_SYNC_HOOK: Hook<FileSyncFn> = Hook::new();
pub fn register_file_sync(f: FileSyncFn) { let _ = FILE_SYNC_HOOK.set(f); }

#[unsafe(no_mangle)]
pub unsafe extern "C-unwind" fn trivfs_S_file_sync(
    cred: *mut trivfs_protid_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
    wait: c_int,
    omitmeta: c_int,
) -> kern_return_t {
    match FILE_SYNC_HOOK.get() {
        Some(f) => f(cred, reply, replyPoly, wait, omitmeta),
        None => { if cred.is_null() { EOPNOTSUPP } else { times::file_sync((*cred).realnode, wait, omitmeta) } },
    }
}

// ── FileUtimensFn ──
pub type FileUtimensFn = unsafe extern "C-unwind" fn(
    cred: *mut trivfs_protid_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
    atime: times::timespec_t,
    mtime: times::timespec_t,
) -> kern_return_t;

static FILE_UTIMENS_HOOK: Hook<FileUtimensFn> = Hook::new();
pub fn register_file_utimens(f: FileUtimensFn) { let _ = FILE_UTIMENS_HOOK.set(f); }

pub type FileUtimesFn = unsafe extern "C-unwind" fn(
    cred: *mut trivfs_protid_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
    atime: times::time_value_t,
    mtime: times::time_value_t,
) -> kern_return_t;

static FILE_UTIMES_HOOK: Hook<FileUtimesFn> = Hook::new();
pub fn register_file_utimes(f: FileUtimesFn) { let _ = FILE_UTIMES_HOOK.set(f); }


#[unsafe(no_mangle)]
pub unsafe extern "C-unwind" fn trivfs_S_file_utimes(
    cred: *mut trivfs_protid_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
    atime: times::time_value_t,
    mtime: times::time_value_t,
) -> kern_return_t {
    match FILE_UTIMES_HOOK.get() {
        Some(f) => f(cred, reply, replyPoly, atime, mtime),
        None => {
            if cred.is_null() { EOPNOTSUPP }
            else { unsafe { times::file_utimes((*cred).realnode, atime, mtime) } }
        },
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C-unwind" fn trivfs_S_file_utimens(
    cred: *mut trivfs_protid_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
    atime: times::timespec_t,
    mtime: times::timespec_t,
) -> kern_return_t {
    match FILE_UTIMENS_HOOK.get() {
        Some(f) => f(cred, reply, replyPoly, atime, mtime),
        None => {
            if cred.is_null() { EOPNOTSUPP }
            else {
                let mut err = unsafe { times::file_utimens((*cred).realnode, atime, mtime) };
                if err == EMIG_BAD_ID || err == EOPNOTSUPP {
                    let atim = times::time_value_t {
                        seconds:      if atime.tv_nsec == -1 { -1 } else { atime.tv_sec as c_int },
                        microseconds: if atime.tv_nsec == -1 { -1 } else { (atime.tv_nsec / 1000) as c_int },
                    };
                    let mtim = times::time_value_t {
                        seconds:      if mtime.tv_nsec == -1 { -1 } else { mtime.tv_sec as c_int },
                        microseconds: if mtime.tv_nsec == -1 { -1 } else { (mtime.tv_nsec / 1000) as c_int },
                    };
                    err = unsafe { times::file_utimes((*cred).realnode, atim, mtim) };
                }
                err
            }
        }
    }
}

// ── FileChmodFn ──
pub type FileChmodFn = unsafe extern "C-unwind" fn(
    cred: *mut trivfs_protid_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
    mode: c_int,
) -> kern_return_t;

static FILE_CHMOD_HOOK: Hook<FileChmodFn> = Hook::new();
pub fn register_file_chmod(f: FileChmodFn) { let _ = FILE_CHMOD_HOOK.set(f); }

#[unsafe(no_mangle)]
pub unsafe extern "C-unwind" fn trivfs_S_file_chmod(
    cred: *mut trivfs_protid_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
    mode: c_int,
) -> kern_return_t {
    match FILE_CHMOD_HOOK.get() {
        Some(f) => f(cred, reply, replyPoly, mode),
        None => { if cred.is_null() { EOPNOTSUPP } else { times::file_chmod((*cred).realnode, mode as c_uint) } },
    }
}

// ── FileChownFn ──
pub type FileChownFn = unsafe extern "C-unwind" fn(
    cred: *mut trivfs_protid_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
    owner: u32,
    group: u32,
) -> kern_return_t;

static FILE_CHOWN_HOOK: Hook<FileChownFn> = Hook::new();
pub fn register_file_chown(f: FileChownFn) { let _ = FILE_CHOWN_HOOK.set(f); }

#[unsafe(no_mangle)]
pub unsafe extern "C-unwind" fn trivfs_S_file_chown(
    cred: *mut trivfs_protid_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
    owner: u32,
    group: u32,
) -> kern_return_t {
    match FILE_CHOWN_HOOK.get() {
        Some(f) => f(cred, reply, replyPoly, owner, group),
        None => { if cred.is_null() { EOPNOTSUPP } else { times::file_chown((*cred).realnode, owner, group) } },
    }
}

// ── FileSetSizeFn ──
pub type FileSetSizeFn = unsafe extern "C-unwind" fn(
    cred: *mut trivfs_protid_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
    size: loff_t,
) -> kern_return_t;

static FILE_SET_SIZE_HOOK: Hook<FileSetSizeFn> = Hook::new();
pub fn register_file_set_size(f: FileSetSizeFn) { let _ = FILE_SET_SIZE_HOOK.set(f); }

#[unsafe(no_mangle)]
pub unsafe extern "C-unwind" fn trivfs_S_file_set_size(
    cred: *mut trivfs_protid_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
    size: loff_t,
) -> kern_return_t {
    match FILE_SET_SIZE_HOOK.get() {
        Some(f) => f(cred, reply, replyPoly, size),
        None => EOPNOTSUPP,
    }
}

// ── FileGetStorageInfoFn ──
pub type FileGetStorageInfoFn = unsafe extern "C-unwind" fn(
    cred: *mut trivfs_protid_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
    ports: *mut portarray_t,
    portsPoly: *mut mach_msg_type_name_t,
    portsCnt: *mut mach_msg_type_number_t,
    ints: *mut intarray_t,
    intsCnt: *mut mach_msg_type_number_t,
    offsets: *mut off_array_t,
    offsetsCnt: *mut mach_msg_type_number_t,
    data: *mut data_t,
    dataCnt: *mut mach_msg_type_number_t,
) -> kern_return_t;

static FILE_GET_STORAGE_INFO_HOOK: Hook<FileGetStorageInfoFn> = Hook::new();
pub fn register_file_get_storage_info(f: FileGetStorageInfoFn) { let _ = FILE_GET_STORAGE_INFO_HOOK.set(f); }

#[unsafe(no_mangle)]
pub unsafe extern "C-unwind" fn trivfs_S_file_get_storage_info(
    cred: *mut trivfs_protid_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
    ports: *mut portarray_t,
    portsPoly: *mut mach_msg_type_name_t,
    portsCnt: *mut mach_msg_type_number_t,
    ints: *mut intarray_t,
    intsCnt: *mut mach_msg_type_number_t,
    offsets: *mut off_array_t,
    offsetsCnt: *mut mach_msg_type_number_t,
    data: *mut data_t,
    dataCnt: *mut mach_msg_type_number_t,
) -> kern_return_t {
    match FILE_GET_STORAGE_INFO_HOOK.get() {
        Some(f) => f(cred, reply, replyPoly, ports, portsPoly, portsCnt, ints, intsCnt, offsets, offsetsCnt, data, dataCnt),
        None => EOPNOTSUPP,  // file-get-storage-info.c:33 — siempre EOPNOTSUPP
    }
}

// ── FileStatfsFn ──
pub type FileStatfsFn = unsafe extern "C-unwind" fn(
    cred: *mut trivfs_protid_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
    info: *mut fsys_statfsbuf_t,
) -> kern_return_t;

static FILE_STATFS_HOOK: Hook<FileStatfsFn> = Hook::new();
pub fn register_file_statfs(f: FileStatfsFn) { let _ = FILE_STATFS_HOOK.set(f); }

#[unsafe(no_mangle)]
pub unsafe extern "C-unwind" fn trivfs_S_file_statfs(
    cred: *mut trivfs_protid_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
    info: *mut fsys_statfsbuf_t,
) -> kern_return_t {
    match FILE_STATFS_HOOK.get() {
        Some(f) => f(cred, reply, replyPoly, info),
        None => {
            if info.is_null() { return ENULLPTR; }
            let fsid_val = fsid();
            let mut stb: fsys_statfsbuf_t = std::mem::zeroed();
            stb.f_type = fstype() as u32;
            stb.f_fsid = fsid_val as u64;
            std::ptr::write(info, stb);
            0
        }
    }
}

// ── FileExecFn ──
pub type FileExecFn = unsafe extern "C-unwind" fn(
    exec_file: *mut trivfs_protid_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
    exec_task: mach_port_t,
    flags: c_int,
    argv: *const c_char,
    argvCnt: mach_msg_type_number_t,
    envp: *const c_char,
    envpCnt: mach_msg_type_number_t,
    fdarray: *const mach_port_t,
    fdarrayCnt: mach_msg_type_number_t,
    portarray: *const mach_port_t,
    portarrayCnt: mach_msg_type_number_t,
    intarray: *const c_int,
    intarrayCnt: mach_msg_type_number_t,
    deallocnames: *const mach_port_name_t,
    deallocnamesCnt: mach_msg_type_number_t,
    destroynames: *const mach_port_name_t,
    destroynamesCnt: mach_msg_type_number_t,
) -> kern_return_t;

static FILE_EXEC_HOOK: Hook<FileExecFn> = Hook::new();
pub fn register_file_exec(f: FileExecFn) { let _ = FILE_EXEC_HOOK.set(f); }
pub fn file_exec_registered() -> bool { FILE_EXEC_HOOK.get().is_some() }

#[unsafe(no_mangle)]
pub unsafe extern "C-unwind" fn trivfs_S_file_exec(
    exec_file: *mut trivfs_protid_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
    exec_task: mach_port_t,
    flags: c_int,
    argv: *const c_char,
    argvCnt: mach_msg_type_number_t,
    envp: *const c_char,
    envpCnt: mach_msg_type_number_t,
    fdarray: *const mach_port_t,
    fdarrayCnt: mach_msg_type_number_t,
    portarray: *const mach_port_t,
    portarrayCnt: mach_msg_type_number_t,
    intarray: *const c_int,
    intarrayCnt: mach_msg_type_number_t,
    deallocnames: *const mach_port_name_t,
    deallocnamesCnt: mach_msg_type_number_t,
    destroynames: *const mach_port_name_t,
    destroynamesCnt: mach_msg_type_number_t,
) -> kern_return_t {
    match FILE_EXEC_HOOK.get() {
        Some(f) => f(exec_file, reply, replyPoly, exec_task, flags, argv, argvCnt, envp, envpCnt, fdarray, fdarrayCnt, portarray, portarrayCnt, intarray, intarrayCnt, deallocnames, deallocnamesCnt, destroynames, destroynamesCnt),
        None => EOPNOTSUPP,
    }
}

// ── FileExecPathsFn ──
pub type FileExecPathsFn = unsafe extern "C-unwind" fn(
    exec_file: *mut trivfs_protid_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
    exec_task: mach_port_t,
    flags: c_int,
    path: *const c_char,
    abspath: *const c_char,
    argv: *const c_char,
    argvCnt: mach_msg_type_number_t,
    envp: *const c_char,
    envpCnt: mach_msg_type_number_t,
    fdarray: *const mach_port_t,
    fdarrayCnt: mach_msg_type_number_t,
    portarray: *const mach_port_t,
    portarrayCnt: mach_msg_type_number_t,
    intarray: *const c_int,
    intarrayCnt: mach_msg_type_number_t,
    deallocnames: *const mach_port_name_t,
    deallocnamesCnt: mach_msg_type_number_t,
    destroynames: *const mach_port_name_t,
    destroynamesCnt: mach_msg_type_number_t,
) -> kern_return_t;

static FILE_EXEC_PATHS_HOOK: Hook<FileExecPathsFn> = Hook::new();
pub fn register_file_exec_paths(f: FileExecPathsFn) { let _ = FILE_EXEC_PATHS_HOOK.set(f); }

#[unsafe(no_mangle)]
pub unsafe extern "C-unwind" fn trivfs_S_file_exec_paths(
    exec_file: *mut trivfs_protid_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
    exec_task: mach_port_t,
    flags: c_int,
    path: *const c_char,
    abspath: *const c_char,
    argv: *const c_char,
    argvCnt: mach_msg_type_number_t,
    envp: *const c_char,
    envpCnt: mach_msg_type_number_t,
    fdarray: *const mach_port_t,
    fdarrayCnt: mach_msg_type_number_t,
    portarray: *const mach_port_t,
    portarrayCnt: mach_msg_type_number_t,
    intarray: *const c_int,
    intarrayCnt: mach_msg_type_number_t,
    deallocnames: *const mach_port_name_t,
    deallocnamesCnt: mach_msg_type_number_t,
    destroynames: *const mach_port_name_t,
    destroynamesCnt: mach_msg_type_number_t,
) -> kern_return_t {
    match FILE_EXEC_PATHS_HOOK.get() {
        Some(f) => f(exec_file, reply, replyPoly, exec_task, flags, path, abspath, argv, argvCnt, envp, envpCnt, fdarray, fdarrayCnt, portarray, portarrayCnt, intarray, intarrayCnt, deallocnames, deallocnamesCnt, destroynames, destroynamesCnt),
        None => EOPNOTSUPP,
    }
}

// ── FileGetfhFn ──
pub type FileGetfhFn = unsafe extern "C-unwind" fn(
    cred: *mut trivfs_protid_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
    filehandle: *mut data_t,
    filehandleCnt: *mut mach_msg_type_number_t,
) -> kern_return_t;

static FILE_GETFH_HOOK: Hook<FileGetfhFn> = Hook::new();
pub fn register_file_getfh(f: FileGetfhFn) { let _ = FILE_GETFH_HOOK.set(f); }

#[unsafe(no_mangle)]
pub unsafe extern "C-unwind" fn trivfs_S_file_getfh(
    cred: *mut trivfs_protid_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
    filehandle: *mut data_t,
    filehandleCnt: *mut mach_msg_type_number_t,
) -> kern_return_t {
    match FILE_GETFH_HOOK.get() {
        Some(f) => f(cred, reply, replyPoly, filehandle, filehandleCnt),
        None => EOPNOTSUPP,
    }
}

// ── FileGetTranslatorFn ──
pub type FileGetTranslatorFn = unsafe extern "C-unwind" fn(
    cred: *mut trivfs_protid_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
    translator: *mut data_t,
    translatorCnt: *mut mach_msg_type_number_t,
) -> kern_return_t;

static FILE_GET_TRANSLATOR_HOOK: Hook<FileGetTranslatorFn> = Hook::new();
pub fn register_file_get_translator(f: FileGetTranslatorFn) { let _ = FILE_GET_TRANSLATOR_HOOK.set(f); }

#[unsafe(no_mangle)]
pub unsafe extern "C-unwind" fn trivfs_S_file_get_translator(
    cred: *mut trivfs_protid_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
    translator: *mut data_t,
    translatorCnt: *mut mach_msg_type_number_t,
) -> kern_return_t {
    match FILE_GET_TRANSLATOR_HOOK.get() {
        Some(f) => f(cred, reply, replyPoly, translator, translatorCnt),
        None => EOPNOTSUPP,
    }
}

// ── FileGetTranslatorCntlFn ──
pub type FileGetTranslatorCntlFn = unsafe extern "C-unwind" fn(
    file: *mut trivfs_protid_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
    translator_cntl: *mut mach_port_t,
    translator_cntlPoly: *mut mach_msg_type_name_t,
) -> kern_return_t;

static FILE_GET_TRANSLATOR_CNTL_HOOK: Hook<FileGetTranslatorCntlFn> = Hook::new();
pub fn register_file_get_translator_cntl(f: FileGetTranslatorCntlFn) { let _ = FILE_GET_TRANSLATOR_CNTL_HOOK.set(f); }

#[unsafe(no_mangle)]
pub unsafe extern "C-unwind" fn trivfs_S_file_get_translator_cntl(
    file: *mut trivfs_protid_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
    translator_cntl: *mut mach_port_t,
    translator_cntlPoly: *mut mach_msg_type_name_t,
) -> kern_return_t {
    match FILE_GET_TRANSLATOR_CNTL_HOOK.get() {
        Some(f) => f(file, reply, replyPoly, translator_cntl, translator_cntlPoly),
        None => EOPNOTSUPP,
    }
}

// ── FileLockFn ──
pub type FileLockFn = unsafe extern "C-unwind" fn(
    lock_file: *mut trivfs_protid_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
    flags: c_int,
) -> kern_return_t;

static FILE_LOCK_HOOK: Hook<FileLockFn> = Hook::new();
pub fn register_file_lock(f: FileLockFn) { let _ = FILE_LOCK_HOOK.set(f); }

#[unsafe(no_mangle)]
pub unsafe extern "C-unwind" fn trivfs_S_file_lock(
    lock_file: *mut trivfs_protid_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
    flags: c_int,
) -> kern_return_t {
    match FILE_LOCK_HOOK.get() {
        Some(f) => f(lock_file, reply, replyPoly, flags),
        None => EOPNOTSUPP,
    }
}

// ── FileLockStatFn ──
pub type FileLockStatFn = unsafe extern "C-unwind" fn(
    cred: *mut trivfs_protid_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
    mystatus: *mut c_int,
    otherstatus: *mut c_int,
) -> kern_return_t;

static FILE_LOCK_STAT_HOOK: Hook<FileLockStatFn> = Hook::new();
pub fn register_file_lock_stat(f: FileLockStatFn) { let _ = FILE_LOCK_STAT_HOOK.set(f); }

#[unsafe(no_mangle)]
pub unsafe extern "C-unwind" fn trivfs_S_file_lock_stat(
    cred: *mut trivfs_protid_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
    mystatus: *mut c_int,
    otherstatus: *mut c_int,
) -> kern_return_t {
    match FILE_LOCK_STAT_HOOK.get() {
        Some(f) => f(cred, reply, replyPoly, mystatus, otherstatus),
        None => EOPNOTSUPP,
    }
}

// ── FileRecordLockFn ──
pub type FileRecordLockFn = unsafe extern "C-unwind" fn(
    file: *mut trivfs_protid_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
    cmd: c_int,
    flock64: *mut flock_t,
    rendezvous: mach_port_t,
) -> kern_return_t;

static FILE_RECORD_LOCK_HOOK: Hook<FileRecordLockFn> = Hook::new();
pub fn register_file_record_lock(f: FileRecordLockFn) { let _ = FILE_RECORD_LOCK_HOOK.set(f); }

#[unsafe(no_mangle)]
pub unsafe extern "C-unwind" fn trivfs_S_file_record_lock(
    file: *mut trivfs_protid_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
    cmd: c_int,
    flock64: *mut flock_t,
    rendezvous: mach_port_t,
) -> kern_return_t {
    match FILE_RECORD_LOCK_HOOK.get() {
        Some(f) => f(file, reply, replyPoly, cmd, flock64, rendezvous),
        None => EOPNOTSUPP,
    }
}

// ── FileNoticeChangesFn ──
pub type FileNoticeChangesFn = unsafe extern "C-unwind" fn(
    file: *mut trivfs_protid_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
    port: mach_port_t,
) -> kern_return_t;

static FILE_NOTICE_CHANGES_HOOK: Hook<FileNoticeChangesFn> = Hook::new();
pub fn register_file_notice_changes(f: FileNoticeChangesFn) { let _ = FILE_NOTICE_CHANGES_HOOK.set(f); }

#[unsafe(no_mangle)]
pub unsafe extern "C-unwind" fn trivfs_S_file_notice_changes(
    file: *mut trivfs_protid_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
    port: mach_port_t,
) -> kern_return_t {
    match FILE_NOTICE_CHANGES_HOOK.get() {
        Some(f) => f(file, reply, replyPoly, port),
        None => EOPNOTSUPP,
    }
}

// ── FileChflagsFn ──
pub type FileChflagsFn = unsafe extern "C-unwind" fn(
    cred: *mut trivfs_protid_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
    flags: c_int,
) -> kern_return_t;

static FILE_CHFLAGS_HOOK: Hook<FileChflagsFn> = Hook::new();
pub fn register_file_chflags(f: FileChflagsFn) { let _ = FILE_CHFLAGS_HOOK.set(f); }

#[unsafe(no_mangle)]
pub unsafe extern "C-unwind" fn trivfs_S_file_chflags(
    cred: *mut trivfs_protid_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
    flags: c_int,
) -> kern_return_t {
    match FILE_CHFLAGS_HOOK.get() {
        Some(f) => f(cred, reply, replyPoly, flags),
        None => if cred.is_null() { EOPNOTSUPP } else { crate::gnuhurd::mig_user::file_chflags((*cred).realnode, flags) },
    }
}

// ── FileChauthorFn ──
pub type FileChauthorFn = unsafe extern "C-unwind" fn(
    cred: *mut trivfs_protid_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
    new_author: u32,
) -> kern_return_t;

static FILE_CHAUTHOR_HOOK: Hook<FileChauthorFn> = Hook::new();
pub fn register_file_chauthor(f: FileChauthorFn) { let _ = FILE_CHAUTHOR_HOOK.set(f); }

#[unsafe(no_mangle)]
pub unsafe extern "C-unwind" fn trivfs_S_file_chauthor(
    cred: *mut trivfs_protid_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
    new_author: u32,
) -> kern_return_t {
    match FILE_CHAUTHOR_HOOK.get() {
        Some(f) => f(cred, reply, replyPoly, new_author),
        None => if cred.is_null() { EOPNOTSUPP } else { crate::gnuhurd::mig_user::file_chauthor((*cred).realnode, new_author) },
    }
}

// ── FileSyncfsFn ──
pub type FileSyncfsFn = unsafe extern "C-unwind" fn(
    cred: *mut trivfs_protid_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
    wait: c_int,
    do_children: c_int,
) -> kern_return_t;

static FILE_SYNCFS_HOOK: Hook<FileSyncfsFn> = Hook::new();
pub fn register_file_syncfs(f: FileSyncfsFn) { let _ = FILE_SYNCFS_HOOK.set(f); }

#[unsafe(no_mangle)]
pub unsafe extern "C-unwind" fn trivfs_S_file_syncfs(
    cred: *mut trivfs_protid_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
    wait: c_int,
    do_children: c_int,
) -> kern_return_t {
    match FILE_SYNCFS_HOOK.get() {
        Some(f) => f(cred, reply, replyPoly, wait, do_children),
        None => if cred.is_null() { EOPNOTSUPP } else { crate::gnuhurd::mig_user::file_sync((*cred).realnode, wait, 0) },
    }
}

// ── FileGetcontrolFn ──
pub type FileGetcontrolFn = unsafe extern "C-unwind" fn(
    cred: *mut trivfs_protid_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
    control: *mut mach_port_t,
    controlPoly: *mut mach_msg_type_name_t,
) -> kern_return_t;

static FILE_GETCONTROL_HOOK: Hook<FileGetcontrolFn> = Hook::new();
pub fn register_file_getcontrol(f: FileGetcontrolFn) { let _ = FILE_GETCONTROL_HOOK.set(f); }

#[unsafe(no_mangle)]
pub unsafe extern "C-unwind" fn trivfs_S_file_getcontrol(
    cred: *mut trivfs_protid_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
    control: *mut mach_port_t,
    controlPoly: *mut mach_msg_type_name_t,
) -> kern_return_t {
    match FILE_GETCONTROL_HOOK.get() {
        Some(f) => f(cred, reply, replyPoly, control, controlPoly),
        None => {
            if cred.is_null() { return EOPNOTSUPP; }
            let c = unsafe { &*cred };
            if c.isroot == 0 { return EPERM; }
            let po = match c.po_ref() { Ok(p) => p, Err(e) => return e };
            if !control.is_null() { *control = ports_get_right(po.cntl as *mut c_void); }
            if !controlPoly.is_null() { *controlPoly = MACH_MSG_TYPE_MAKE_SEND; }
            0
        },
    }
}

// ── FileGetlinknodeFn ──
pub type FileGetlinknodeFn = unsafe extern "C-unwind" fn(
    cred: *mut trivfs_protid_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
    linknode: *mut mach_port_t,
    linknodePoly: *mut mach_msg_type_name_t,
) -> kern_return_t;

static FILE_GETLINKNODE_HOOK: Hook<FileGetlinknodeFn> = Hook::new();
pub fn register_file_getlinknode(f: FileGetlinknodeFn) { let _ = FILE_GETLINKNODE_HOOK.set(f); }

#[unsafe(no_mangle)]
pub unsafe extern "C-unwind" fn trivfs_S_file_getlinknode(
    cred: *mut trivfs_protid_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
    linknode: *mut mach_port_t,
    linknodePoly: *mut mach_msg_type_name_t,
) -> kern_return_t {
    match FILE_GETLINKNODE_HOOK.get() {
        Some(f) => f(cred, reply, replyPoly, linknode, linknodePoly),
        None => {
            if cred.is_null() { return EOPNOTSUPP; }
            if !linknode.is_null() { *linknode = unsafe { (*cred).realnode }; }
            if !linknodePoly.is_null() { *linknodePoly = MACH_MSG_TYPE_COPY_SEND; }
            0
        },
    }
}

// ── FileGetFsOptionsFn ──
pub type FileGetFsOptionsFn = unsafe extern "C-unwind" fn(
    cred: *mut trivfs_protid_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
    data: *mut data_t,
    len: *mut mach_msg_type_number_t,
) -> kern_return_t;

static FILE_GET_FS_OPTIONS_HOOK: Hook<FileGetFsOptionsFn> = Hook::new();
pub fn register_file_get_fs_options(f: FileGetFsOptionsFn) { let _ = FILE_GET_FS_OPTIONS_HOOK.set(f); }

#[unsafe(no_mangle)]
pub unsafe extern "C-unwind" fn trivfs_S_file_get_fs_options(
    cred: *mut trivfs_protid_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
    data: *mut data_t,
    len: *mut mach_msg_type_number_t,
) -> kern_return_t {
    match FILE_GET_FS_OPTIONS_HOOK.get() {
        Some(f) => f(cred, reply, replyPoly, data, len),
        None => {
            if cred.is_null() { return EOPNOTSUPP; }
            let mut argz: *mut c_char = std::ptr::null_mut();
            let mut argz_len: usize = 0;
            // argz_add(&argz, &argz_len, program_invocation_name)
            let name = unsafe { std::ffi::CStr::from_ptr(program_invocation_name) }
                .to_str().unwrap_or("");
            let mut err = unsafe { vec_to_argz(&mut argz, &mut argz_len, name) };
            if err != 0 { return err; }
            let c = unsafe { &*cred };
            let cntl = match c.po_ref() { Ok(p) => p.cntl, Err(e) => return e };
            err = unsafe { trivfs_append_args(cntl, &mut argz, &mut argz_len) };
            if err != 0 {
                unsafe { libc::free(argz as *mut c_void); }
                return err;
            }
            err = unsafe { iohelp_return_malloced_buffer(argz, argz_len, data, len) };
            err
        },
    }
}

// ── FileReparentFn ──
pub type FileReparentFn = unsafe extern "C-unwind" fn(
    cred: *mut trivfs_protid_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
    parent: mach_port_t,
    new_file: *mut mach_port_t,
    new_filePoly: *mut mach_msg_type_name_t,
) -> kern_return_t;

static FILE_REPARENT_HOOK: Hook<FileReparentFn> = Hook::new();
pub fn register_file_reparent(f: FileReparentFn) { let _ = FILE_REPARENT_HOOK.set(f); }

#[unsafe(no_mangle)]
pub unsafe extern "C-unwind" fn trivfs_S_file_reparent(
    cred: *mut trivfs_protid_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
    parent: mach_port_t,
    new_file: *mut mach_port_t,
    new_filePoly: *mut mach_msg_type_name_t,
) -> kern_return_t {
    match FILE_REPARENT_HOOK.get() {
        Some(f) => f(cred, reply, replyPoly, parent, new_file, new_filePoly),
        None => {
            let ret = unsafe { trivfs_S_io_duplicate(cred, reply, replyPoly, new_file, new_filePoly) };
            if ret == 0 {
                unsafe { mach_port_deallocate(mach_task_self(), parent); }
            }
            ret
        },
    }
}

unsafe extern "C" {
    static program_invocation_name: *const c_char;
}