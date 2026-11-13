use std::ffi::{c_char, c_int, c_uint, c_void};
use crate::gnuhurd::trivfs::hooks::Hook;
use std::mem::offset_of;

use crate::gnumach::kern_return::kern_return_t;
use crate::gnumach::port::{mach_port_t, mach_port_mod_refs, MACH_PORT_RIGHT_SEND};
use crate::gnumach::message::{mach_msg_type_name_t, mach_msg_type_number_t, MACH_MSG_TYPE_MAKE_SEND};
use crate::gnumach::task::mach_task_self;
use crate::gnuhurd::fcntl::{O_CREAT, O_EXCL, O_EXEC, O_HURD, O_NOLINK, O_NOTRANS, O_READ, O_WRITE};
use crate::gnuhurd::io::{data_t, iohelp_dup_iouser, iohelp_free_iouser, iouser};
use crate::gnuhurd::ports::{ports_get_right, ports_port_deref};
use crate::gnuhurd::trivfs::types::trivfs_protid_t;
use crate::gnuhurd::trivfs::hooks::{load_check_access, load_check_open};
use crate::gnuhurd::trivfs::open::trivfs_open;
use crate::gnuhurd::trivfs::times;
use crate::gnuhurd::types::FS_RETRY_NORMAL;
use crate::gnumach::error::{EOPNOTSUPP, ENOTDIR, EXDEV, EACCES, ENULLPTR};
use crate::gnumach::boolean::boolean_t;
use crate::gnumach::vm_types::vm_size_t;
use crate::debug;

// ── Function types ──

pub type DirLookupFn = unsafe extern "C-unwind" fn(
    cred: *mut trivfs_protid_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
    name: *const c_char,
    flags: c_int,
    mode: u32,
    retry_type: *mut c_int,
    retry_name: *mut c_char,
    retrypt: *mut mach_port_t,
    retrypt_type: *mut mach_msg_type_name_t,
) -> kern_return_t;

pub type DirReaddirFn = unsafe extern "C-unwind" fn(
    cred: *mut trivfs_protid_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
    data: *mut data_t,
    datalen: *mut mach_msg_type_number_t,
    data_dealloc: *mut boolean_t,
    entry: c_int,
    nentries: c_int,
    bufsiz: vm_size_t,
    amount: *mut c_int,
) -> kern_return_t;

pub type DirUnlinkFn = unsafe extern "C-unwind" fn(
    cred: *mut trivfs_protid_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
    name: *const c_char,
) -> kern_return_t;

pub type DirRmdirFn = unsafe extern "C-unwind" fn(
    cred: *mut trivfs_protid_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
    name: *const c_char,
) -> kern_return_t;

pub type DirMkdirFn = unsafe extern "C-unwind" fn(
    cred: *mut trivfs_protid_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
    name: *const c_char,
    mode: u32,
) -> kern_return_t;

pub type DirMkfileFn = unsafe extern "C-unwind" fn(
    cred: *mut trivfs_protid_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
    flags: c_int,
    mode: u32,
    newnode: *mut mach_port_t,
    newnodePoly: *mut mach_msg_type_name_t,
) -> kern_return_t;

pub type DirLinkFn = unsafe extern "C-unwind" fn(
    dir: *mut trivfs_protid_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
    file: *mut trivfs_protid_t,
    name: *const c_char,
    excl: c_int,
) -> kern_return_t;

pub type DirRenameFn = unsafe extern "C-unwind" fn(
    cred: *mut trivfs_protid_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
    name: *const c_char,
    cred2: *mut trivfs_protid_t,
    name2: *const c_char,
    excl: c_int,
) -> kern_return_t;

// ── Hooks ──

static DIR_LOOKUP_HOOK: Hook<DirLookupFn> = Hook::new();
static DIR_READDIR_HOOK: Hook<DirReaddirFn> = Hook::new();
static DIR_UNLINK_HOOK: Hook<DirUnlinkFn> = Hook::new();
static DIR_RMDIR_HOOK: Hook<DirRmdirFn> = Hook::new();
static DIR_MKDIR_HOOK: Hook<DirMkdirFn> = Hook::new();
static DIR_MKFILE_HOOK: Hook<DirMkfileFn> = Hook::new();
static DIR_LINK_HOOK: Hook<DirLinkFn> = Hook::new();
static DIR_RENAME_HOOK: Hook<DirRenameFn> = Hook::new();

// ── register API ──

pub fn register_dir_lookup(f: DirLookupFn) {
    let _ = DIR_LOOKUP_HOOK.set(f);
}

pub fn register_dir_readdir(f: DirReaddirFn) {
    let _ = DIR_READDIR_HOOK.set(f);
}
pub fn register_dir_unlink(f: DirUnlinkFn) { let _ = DIR_UNLINK_HOOK.set(f); }
pub fn register_dir_rmdir(f: DirRmdirFn) { let _ = DIR_RMDIR_HOOK.set(f); }
pub fn register_dir_mkdir(f: DirMkdirFn) { let _ = DIR_MKDIR_HOOK.set(f); }
pub fn register_dir_mkfile(f: DirMkfileFn) { let _ = DIR_MKFILE_HOOK.set(f); }
pub fn register_dir_link(f: DirLinkFn) { let _ = DIR_LINK_HOOK.set(f); }
pub fn register_dir_rename(f: DirRenameFn) { let _ = DIR_RENAME_HOOK.set(f); }

// ── Symbols visibles by linker (default EOPNOTSUPP) ──

#[unsafe(no_mangle)]
pub unsafe extern "C-unwind" fn trivfs_S_dir_lookup(
    cred: *mut trivfs_protid_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
    name: *const c_char,
    flags: c_int,
    mode: u32,
    retry_type: *mut c_int,
    retry_name: *mut c_char,
    retrypt: *mut mach_port_t,
    retrypt_type: *mut mach_msg_type_name_t,
) -> kern_return_t {
    let hook = DIR_LOOKUP_HOOK.get();
    let ret = match hook {
        Some(f) => f(cred, reply, replyPoly, name, flags, mode,
                     retry_type, retry_name, retrypt, retrypt_type),
        None => (|| {
            if cred.is_null() { return EOPNOTSUPP; }
            let c = unsafe { &*cred };
            let po = match c.po_ref() { Ok(p) => p, Err(e) => return e };
            if name.is_null() { return ENULLPTR; }
            if *name != 0 { return ENOTDIR; }                       // filename[0]
            let flags = flags & O_HURD & !(O_CREAT|O_EXCL|O_NOLINK|O_NOTRANS);
            let mut perms: c_int = 0;                               // check_access
            match load_check_access() {
                Some(f) => { let err = f(po.cntl, c.user, c.realnode, &mut perms);
                             if err != 0 { return err; } }
                None => { let err = times::file_check_access(c.realnode, &mut perms);
                          if err != 0 { return err; } }
            }
            let req = (flags as c_uint) & (O_READ|O_WRITE|O_EXEC);
            if (req & perms as c_uint) != req { return EACCES; }
            let mut err = 0;                                        // check_open
            if let Some(f) = load_check_open() {
                err = f(po.cntl, c.user, flags);
            }
            if err == 0 {                                           // open
                let mut user: *mut iouser = std::ptr::null_mut();
                err = iohelp_dup_iouser(&mut user, c.user);
                if err == 0 {
                    let mut newcred: *mut trivfs_protid_t = std::ptr::null_mut();
                    err = trivfs_open(po.cntl, user, flags as c_uint, c.realnode, &mut newcred);
                    if err != 0 { iohelp_free_iouser(user); }
                    else {
                        // #11: the +1 balances the `realnode` dealloc in
                        // trivfs_clean_protid; C ignores the return (dir-lookup.c:77).
                        mach_port_mod_refs(mach_task_self(), c.realnode, MACH_PORT_RIGHT_SEND, 1);
                        *retry_type = FS_RETRY_NORMAL;
                        *retry_name = 0;
                        *retrypt = ports_get_right(newcred as *mut c_void);
                        *retrypt_type = MACH_MSG_TYPE_MAKE_SEND;
                        ports_port_deref(newcred as *mut c_void);
                    }
                }
            }
            err
        })(),
    };
    debug!("[DEBUG] trivfs_S_dir_lookup: hook={:?} cred={:p} name={:p} flags=0x{:x} mode=0x{:x} ret={}",
           hook, cred, name, flags, mode, ret);
    ret
}

#[unsafe(no_mangle)]
pub unsafe extern "C-unwind" fn trivfs_S_dir_readdir(
    cred: *mut trivfs_protid_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
    data: *mut data_t,
    datalen: *mut mach_msg_type_number_t,
    data_dealloc: *mut boolean_t,
    entry: c_int,
    nentries: c_int,
    bufsiz: vm_size_t,
    amount: *mut c_int,
) -> kern_return_t {
    let hook = DIR_READDIR_HOOK.get();
    let ret = match hook {
        Some(f) => f(cred, reply, replyPoly, data, datalen, data_dealloc,
                     entry, nentries, bufsiz, amount),
        None => if cred.is_null() { EOPNOTSUPP } else { ENOTDIR },
    };
    debug!("[DEBUG] trivfs_S_dir_readdir: hook={:?} cred={:p} entry={} nentries={} bufsiz={} ret={}",
           hook, cred, entry, nentries, bufsiz, ret);
    ret
}

#[unsafe(no_mangle)]
pub unsafe extern "C-unwind" fn trivfs_S_dir_unlink(
    cred: *mut trivfs_protid_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
    name: *const c_char,
) -> kern_return_t {
    let hook = DIR_UNLINK_HOOK.get();
    let ret = match hook {
        Some(f) => f(cred, reply, replyPoly, name),
        None => if cred.is_null() { EOPNOTSUPP } else { ENOTDIR }
    };
    debug!("[DEBUG] trivfs_S_dir_unlink: hook={:?} cred={:p} name={:p} ret={}",
           hook, cred, name, ret);
    ret
}

#[unsafe(no_mangle)]
pub unsafe extern "C-unwind" fn trivfs_S_dir_rmdir(
    cred: *mut trivfs_protid_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
    name: *const c_char,
) -> kern_return_t {
    let hook = DIR_RMDIR_HOOK.get();
    let ret = match hook {
        Some(f) => f(cred, reply, replyPoly, name),
        None => if cred.is_null() { EOPNOTSUPP } else { ENOTDIR },
    };
    debug!("[DEBUG] trivfs_S_dir_rmdir: hook={:?} cred={:p} name={:p} ret={}",
           hook, cred, name, ret);
    ret
}

#[unsafe(no_mangle)]
pub unsafe extern "C-unwind" fn trivfs_S_dir_mkdir(
    cred: *mut trivfs_protid_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
    name: *const c_char,
    mode: u32,
) -> kern_return_t {
    let hook = DIR_MKDIR_HOOK.get();
    let ret = match hook {
        Some(f) => f(cred, reply, replyPoly, name, mode),
        None => if cred.is_null() { EOPNOTSUPP } else { ENOTDIR },
    };
    debug!("[DEBUG] trivfs_S_dir_mkdir: hook={:?} cred={:p} name={:p} mode=0x{:x} ret={}",
           hook, cred, name, mode, ret);
    ret
}

#[unsafe(no_mangle)]
pub unsafe extern "C-unwind" fn trivfs_S_dir_mkfile(
    cred: *mut trivfs_protid_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
    flags: c_int,
    mode: u32,
    newnode: *mut mach_port_t,
    newnodePoly: *mut mach_msg_type_name_t,
) -> kern_return_t {
    let hook = DIR_MKFILE_HOOK.get();
    let ret = match hook {
        Some(f) => f(cred, reply, replyPoly, flags, mode, newnode, newnodePoly),
        None => if cred.is_null() { EOPNOTSUPP } else { ENOTDIR },
    };
    debug!("[DEBUG] trivfs_S_dir_mkfile: hook={:?} cred={:p} flags=0x{:x} mode=0x{:x} ret={}",
           hook, cred, flags, mode, ret);
    ret
}

#[unsafe(no_mangle)]
pub unsafe extern "C-unwind" fn trivfs_S_dir_link(
    dir: *mut trivfs_protid_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
    file: *mut trivfs_protid_t,
    name: *const c_char,
    excl: c_int,
) -> kern_return_t {
    let hook = DIR_LINK_HOOK.get();
    let ret = match hook {
        Some(f) => f(dir, reply, replyPoly, file, name, excl),
        None => {
            if file.is_null() { EOPNOTSUPP }
            else if dir.is_null() { EXDEV }
            else { ENOTDIR }
        },
    };
    debug!("[DEBUG] trivfs_S_dir_link: hook={:?} dir={:p} file={:p} name={:p} excl={} ret={}",
           hook, dir, file, name, excl, ret);
    ret
}

#[unsafe(no_mangle)]
pub unsafe extern "C-unwind" fn trivfs_S_dir_rename(
    cred: *mut trivfs_protid_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
    name: *const c_char,
    cred2: *mut trivfs_protid_t,
    name2: *const c_char,
    excl: c_int,
) -> kern_return_t {
    let hook = DIR_RENAME_HOOK.get();
    let ret = match hook {
        Some(f) => f(cred, reply, replyPoly, name, cred2, name2, excl),
        None => {
            if cred.is_null() { EOPNOTSUPP }
            else if cred2.is_null() { EXDEV }
            else { ENOTDIR }
        },
    };
    debug!("[DEBUG] trivfs_S_dir_rename: hook={:?} cred={:p} name={:p} cred2={:p} name2={:p} excl={} ret={}",
           hook, cred, name, cred2, name2, excl, ret);
    ret
}

// ── DirNoticeChangesFn ──
pub type DirNoticeChangesFn = unsafe extern "C-unwind" fn(
    directory: *mut trivfs_protid_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
    port: mach_port_t,
) -> kern_return_t;

static DIR_NOTICE_CHANGES_HOOK: Hook<DirNoticeChangesFn> = Hook::new();
pub fn register_dir_notice_changes(f: DirNoticeChangesFn) { let _ = DIR_NOTICE_CHANGES_HOOK.set(f); }

#[unsafe(no_mangle)]
pub unsafe extern "C-unwind" fn trivfs_S_dir_notice_changes(
    directory: *mut trivfs_protid_t,
    reply: mach_port_t,
    replyPoly: mach_msg_type_name_t,
    port: mach_port_t,
) -> kern_return_t {
    match DIR_NOTICE_CHANGES_HOOK.get() {
        Some(f) => f(directory, reply, replyPoly, port),
        None => if directory.is_null() { EOPNOTSUPP } else { ENOTDIR },
    }
}

// ── Helpers ──

pub unsafe fn add_dirent(
    ptr: *mut u8,
    name: &str,
    ino: u64,
    dtype: u8,
    remaining: usize,
) -> Option<*mut u8> {
    let name_bytes = name.as_bytes();
    let namlen = name_bytes.len().min(255);

    let mut d: Box<libc::dirent64> = Box::new(std::mem::zeroed());

    d.d_ino = ino;
    d.d_type = dtype;
    std::ptr::copy_nonoverlapping(name_bytes.as_ptr(), d.d_name.as_mut_ptr() as *mut u8, namlen);
    *d.d_name.as_mut_ptr().add(namlen) = 0;

    let header_size = offset_of!(libc::dirent64, d_name);
    let total = header_size + namlen + 1;
    let reclen = ((total + 3) & !3) as u16;

    // Defensive bound of the destination buffer: if the entry does not fit,
    // None (the caller decides: truncate the list, do not write OOB).
    if reclen as usize > remaining { return None; }

    d.d_reclen = reclen;

    std::ptr::copy_nonoverlapping(
        &*d as *const libc::dirent64 as *const u8,
        ptr,
        reclen as usize,
    );
    Some(ptr.add(reclen as usize))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::offset_of;

    // #18a: add_dirent honors the destination buffer bound (None if it does
    // not fit) and advances the pointer by d_reclen when it fits.
    #[test]
    fn add_dirent_bounds_and_advance() {
        let mut buf = [0u8; 512];
        let base = buf.as_mut_ptr() as *mut u8;

        let p = unsafe { add_dirent(base, "abc", 7, 8, buf.len()) };
        let p = p.expect("the entry must fit in 512 bytes");
        let reclen = unsafe {
            core::ptr::read_unaligned(base.add(offset_of!(libc::dirent64, d_reclen)) as *const u16)
        } as usize;
        assert_eq!(p as usize - base as usize, reclen,
            "the pointer must advance exactly d_reclen");

        // insufficient remaining → None (no OOB write)
        assert!(unsafe { add_dirent(base, "abc", 7, 8, 1) }.is_none());
        // exact remaining → fits (reclen <= 512 and << the buffer)
        assert!(unsafe { add_dirent(base, "abc", 7, 8, reclen) }.is_some());
    }
}