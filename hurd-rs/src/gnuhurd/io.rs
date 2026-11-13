//===========================================================================//
// crate::gnuhurd::io                                                        //
//---------------------------------------------------------------------------//
// From github - gnuhurd                                                     //
//===========================================================================//

use std::ffi::{c_void, c_char, c_int, c_uint, c_ulong, c_longlong};
#[cfg(target_pointer_width = "64")]
use std::ffi::c_long;
use libc::{uid_t, dev_t, nlink_t, blksize_t, time_t};

use crate::gnumach::port::mach_port_t;

use std::mem::size_of;
use std::ptr;
use crate::gnumach::error::mach_error_t;
use crate::gnumach::error::{ENOMEM, ENULLPTR, EINVAL, EOVERFLOW};

//---------------------------------------------------------------------------//
// Types                                                                     //
//---------------------------------------------------------------------------//

pub type io_t         = mach_port_t;
pub type file_t       = mach_port_t;
pub type off64_t      = c_longlong;
pub type const_data_t = *const c_char;
pub type data_t       = *mut c_char;
pub type io_statbuf_t = io_statbuf;


#[cfg(target_pointer_width = "32")]
pub type loff_t = c_longlong;

#[cfg(target_pointer_width = "64")]
pub type loff_t = c_long;

pub type portarray_t = *mut mach_port_t;    // array[] of mach_port_send_t
pub type intarray_t  = *mut c_int;
pub type off_array_t = *mut loff_t;         // array[] of loff_t

//---------------------------------------------------------------------------//
// Structs                                                                   //
//---------------------------------------------------------------------------//

#[repr(C)]
#[derive(Copy, Clone)]
pub struct idvec {
    pub ids: *mut uid_t,
    pub num: c_uint,
    pub alloced: c_uint,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct iouser {
    pub uids: *mut idvec,
    pub gids: *mut idvec,
    pub hook: *mut c_void,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct io_statbuf {
    pub st_fstype: u32,
    pub st_fsid: u64,
    pub st_ino: u64,
    pub st_gen: u32,
    pub st_rdev: dev_t,
    pub st_mode: u32,
    pub st_nlink: nlink_t,
    pub st_uid: u32,
    pub st_gid: u32,
    pub st_size: i64,
    pub st_atime: time_t,
    pub st_atimensec: c_ulong,
    pub st_mtime: time_t,
    pub st_mtimensec: c_ulong,
    pub st_ctime: time_t,
    pub st_ctimensec: c_ulong,
    pub st_blksize: blksize_t,
    pub st_blocks: i64,
    pub st_author: u32,
    pub st_flags: u32,
    pub st_spare: [i32; 8]
}
#[cfg(target_pointer_width = "32")]
const _: () = assert!(size_of::<io_statbuf>() == 128); //compilation guard
#[cfg(target_pointer_width = "64")]
const _: () = assert!(size_of::<io_statbuf>() == 176); //compilation guard

#[cfg(target_pointer_width = "32")]
const _: () = assert!(size_of::<fsys_statfsbuf_t>() == 88); // i686 wire layout
#[cfg(target_pointer_width = "64")]
const _: () = assert!(size_of::<fsys_statfsbuf_t>() == 96); // amd64, if apply

#[repr(C)]
pub struct fsys_statfsbuf_t {
    pub f_type: u32,
    pub f_bsize: u32,
    pub f_blocks: u64,
    pub f_bfree: u64,
    pub f_bavail: u64,
    pub f_files: u64,
    pub f_ffree: u64,
    pub f_fsid: u64,
    pub f_namelen: u32,
    pub f_favail: u64,
    pub f_frsize: u32,
    pub f_flag: u32,
    pub f_spare: [u32; 3],
}

//---------------------------------------------------------------------------//
// Constants                                                                 //
//---------------------------------------------------------------------------//

pub const SELECT_READ:  u32 = 1;
pub const SELECT_WRITE: u32 = 2;
pub const SELECT_URG:   u32 = 4;

pub const SEEK_SET: c_uint = 0;
pub const SEEK_CUR: c_uint = 1;
pub const SEEK_END: c_uint = 2;

//---------------------------------------------------------------------------//
// Helper functions                                                          //
//---------------------------------------------------------------------------//

// Asegura que en un 'idvec' caben 'num' elemenmtos
pub unsafe fn idvec_ensure(v: *mut idvec, num: c_uint) -> mach_error_t {
    let v = unsafe { &mut *v };
    if num > v.alloced {
        let Some(bytes) = (num as usize).checked_mul(size_of::<uid_t>()) else { return ENOMEM };
        let new_ids = unsafe { libc::realloc(v.ids as *mut c_void, bytes) } as *mut uid_t;
        if new_ids.is_null() { return ENOMEM; }
        v.ids = new_ids;
        v.alloced = num;
    }
    0
}

// Copia 'num' ids de 'src' a 'v'
pub unsafe fn idvec_set_ids(v: *mut idvec, src: *const uid_t, num: c_uint) -> mach_error_t {
    if v.is_null() || (num > 0 && src.is_null()) { return EINVAL; }
    let old = unsafe { (*v).ids } as *const uid_t;
    // SRC es el propio buffer de V: no hay nada que copiar, y un realloc lo invalidaría.
    if src == old && num <= unsafe { (*v).num } {
        unsafe { (*v).num = num; }
        return 0;
    }
    let err = unsafe { idvec_ensure(v, num) };
    if err != 0 { return err; }
    let d = unsafe { &mut *v };
    if num > 0 {
        unsafe { ptr::copy(src, d.ids, num as usize); } // memmove: tolera solapamiento
    }
    d.num = num;
    0
}

// Crea un idvec vacio
pub unsafe fn make_idvec() -> *mut idvec {
    let v = unsafe { libc::malloc(size_of::<idvec>()) } as *mut idvec;
    if !v.is_null() {
        unsafe { v.write(idvec { ids: ptr::null_mut(), num: 0, alloced: 0 }); }
    }
    v
}

// Libera el contenido de un idvec
pub unsafe fn idvec_free_contents(v: *mut idvec) {
    if v.is_null() { return; }
    let v = unsafe { &mut *v };
    unsafe { libc::free(v.ids as *mut c_void); }   // free(NULL) es válido
    v.ids = ptr::null_mut();
    v.num = 0;
    v.alloced = 0;
}

// Libera un idvec eliminando antes su contenido
pub unsafe fn idvec_free(v: *mut idvec) {
    if v.is_null() { return; }
    unsafe {
        idvec_free_contents(v);
        libc::free(v as *mut c_void);
    }
}

pub unsafe fn idvec_set(dst: *mut idvec, src: *const idvec) -> mach_error_t {
    let s = unsafe { &*src };
    unsafe { idvec_set_ids(dst, s.ids, s.num) }
}

/// Reserva un iouser con malloc (compatible con iohelp_free_iouser de C) y lo inicializa.
unsafe fn iouser_new(uids: *mut idvec, gids: *mut idvec) -> *mut iouser {
    let p = unsafe { libc::malloc(size_of::<iouser>()) } as *mut iouser;
    if !p.is_null() {
        unsafe { p.write(iouser { uids, gids, hook: ptr::null_mut() }); }
    }
    p
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn iohelp_dup_iouser(
    clone: *mut *mut iouser,
    iouser: *const iouser,
) -> mach_error_t {
    unsafe{
        if iouser.is_null() {
            if !clone.is_null() { *clone = std::ptr::null_mut(); }
            return ENULLPTR;
        }
        let new_ = iouser_new(ptr::null_mut(), ptr::null_mut());
        if new_.is_null() { if !clone.is_null() { *clone = ptr::null_mut(); } return ENOMEM; }
        
        let nr = &mut *new_;
        let uids = make_idvec();
        let gids = make_idvec();
        nr.uids = uids;
        nr.gids = gids;
        nr.hook = ptr::null_mut();

        if uids.is_null() || gids.is_null() {
            if !uids.is_null() { idvec_free(uids); }
            if !gids.is_null() { idvec_free(gids); }
            libc::free(new_ as *mut c_void);
            if !clone.is_null() { *clone = ptr::null_mut(); }
            return ENOMEM;
        }

        let i = &*iouser;
        let mut err = idvec_set(uids, i.uids);
        if err == 0 { err = idvec_set(gids, i.gids); }
        if err != 0 {
            idvec_free(uids);
            idvec_free(gids);
            libc::free(new_ as *mut c_void);
            if !clone.is_null() { *clone = ptr::null_mut(); }
            return err;
        }
        (*clone) = new_;
    }
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn iohelp_free_iouser(iouser: *mut iouser) {
    if iouser.is_null() { return; }
    let i = unsafe { &*iouser };
    unsafe {
        idvec_free(i.uids);
        idvec_free(i.gids);
        libc::free(iouser as *mut c_void);
    }
}

/// iohelp_return_malloced_buffer (libiohelp/return-buffer.c): put a malloced
/// buffer BUF (LEN bytes) into *RBUF/*RLEN suitable for returning from a Mach
/// RPC. If LEN > 0, BUF is freed regardless of errors.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn iohelp_return_malloced_buffer(
    buf: *mut c_char,
    len: usize,
    rbuf: *mut *mut c_char,
    rlen: *mut crate::gnumach::message::mach_msg_type_number_t,
) -> mach_error_t {
    let mut err: mach_error_t = 0;
    let rl = unsafe { &mut *rlen };
    if (*rl as usize) < len {
        if len > u32::MAX as usize { 
            libc::free(buf as *mut c_void); 
            return EOVERFLOW; 
        }
        let mapped = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_ANON,
                -1,
                0,
            )
        };
        if mapped == libc::MAP_FAILED {
            err = *libc::__errno_location() as mach_error_t;
        } else {
            unsafe { *rbuf = mapped as *mut c_char; }
        }
    }
    if err == 0 {
        if len > 0 {
            unsafe { std::ptr::copy_nonoverlapping(buf, *rbuf, len); }
        }
        *rl = len as u32;
    }
    unsafe { libc::free(buf as *mut c_void); }
    err
}

/// iohelp_create_complex_iouser (libiohelp/iouser-create.c): build an iouser
/// from the given uids/gids arrays.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn iohelp_create_complex_iouser(
    user: *mut *mut iouser,
    uvec: *const uid_t,
    nuids: c_uint,
    gvec: *const uid_t,
    ngids: c_uint,
) -> mach_error_t {
    unsafe {
        let uids = make_idvec();
        if uids.is_null() {
            if !user.is_null() { *user = std::ptr::null_mut(); }
            return ENOMEM;
        }
        let gids = make_idvec();
        if gids.is_null() {
            idvec_free(uids);
            if !user.is_null() { *user = std::ptr::null_mut(); }
            return ENOMEM;
        }
        let mut err = idvec_set_ids(uids, uvec, nuids);
        if err == 0 { err = idvec_set_ids(gids, gvec, ngids); }
        if err != 0 {
            idvec_free(uids);
            idvec_free(gids);
            if !user.is_null() { *user = std::ptr::null_mut(); }
            return err;
        }
        let new_ = iouser_new(ptr::null_mut(), ptr::null_mut());
        if new_.is_null() {
            idvec_free(uids);
            idvec_free(gids);
            if !user.is_null() { *user = std::ptr::null_mut(); }
            return ENOMEM;
        }
        let n = &mut *new_;
        n.uids = uids;
        n.gids = gids;
        n.hook = std::ptr::null_mut();
        if !user.is_null() { *user = new_; }
        0
    }
}

/// iohelp_create_iouser (libiohelp/iouser-create.c): wrap existing idvecs.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn iohelp_create_iouser(
    user: *mut *mut iouser,
    uids: *mut idvec,
    gids: *mut idvec,
) -> mach_error_t {
    unsafe {
        let new_ = iouser_new(ptr::null_mut(), ptr::null_mut());
        if new_.is_null() {
            if !user.is_null() { *user = std::ptr::null_mut(); }
            return ENOMEM;
        }
        let n = &mut *new_;
        n.uids = uids;
        n.gids = gids;
        n.hook = std::ptr::null_mut();
        if !user.is_null() { *user = new_; }
        0
    }
}

#[link(name = "shouldbeinlibc", kind = "dylib")]
unsafe extern "C" {
    /// idvec_add (libshouldbeinlibc, <idvec.h>): add a uid to an idvec.
    pub fn idvec_add(v: *mut idvec, id: uid_t) -> mach_error_t;
}

/// iohelp_reauth (libiohelp/iouser-reauth.c): conduct a reauthentication
/// transaction against AUTHSERVER, returning a new iouser in *USER.
/// REND_PORT is the rendezvous port, NEWRIGHT the new right to hand the user.
/// Only built with the trivfs feature: it calls the auth_server_authenticate
/// MIG client stub (gnuhurd::mig_user), which is feature-gated too.
#[cfg(feature = "trivfs")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn iohelp_reauth(
    user: *mut *mut iouser,
    authserver: mach_port_t,
    rend_port: mach_port_t,
    newright: mach_port_t,
    permit_failure: c_int,
) -> mach_error_t {
    unsafe {
        let new = iouser_new(ptr::null_mut(), ptr::null_mut());
        if new.is_null() {
            if !user.is_null() { *user = std::ptr::null_mut(); }
            return ENOMEM;
        }
        (*new).uids = make_idvec();
        (*new).gids = make_idvec();
        if (*new).uids.is_null() || (*new).gids.is_null() {
            if !(*new).uids.is_null() { idvec_free((*new).uids); }
            if !(*new).gids.is_null() { idvec_free((*new).gids); }
            libc::free(new as *mut c_void);
            if !user.is_null() { *user = std::ptr::null_mut(); }
            return ENOMEM;
        }

        // Stack buffers for the 4 id arrays (20 elements each like the C).
        const BUFN: usize = 20;
        let gen_uids: [uid_t; BUFN] = [0; BUFN];
        let gen_gids: [uid_t; BUFN] = [0; BUFN];
        let aux_uids: [uid_t; BUFN] = [0; BUFN];
        let aux_gids: [uid_t; BUFN] = [0; BUFN];

        let mut eup = gen_uids.as_ptr();
        let mut eup_len: crate::gnumach::message::mach_msg_type_number_t = BUFN as u32;
        let mut aup = aux_uids.as_ptr();
        let mut aup_len: crate::gnumach::message::mach_msg_type_number_t = BUFN as u32;
        let mut egp = gen_gids.as_ptr();
        let mut egp_len: crate::gnumach::message::mach_msg_type_number_t = BUFN as u32;
        let mut agp = aux_gids.as_ptr();
        let mut agp_len: crate::gnumach::message::mach_msg_type_number_t = BUFN as u32;

        let mut err: mach_error_t = loop {
            let e = crate::gnuhurd::mig_user::auth_server_authenticate(
                authserver, rend_port, newright,
                &mut eup, &mut eup_len,
                &mut aup, &mut aup_len,
                &mut egp, &mut egp_len,
                &mut agp, &mut agp_len,
            );
            if e != crate::gnumach::error::EINTR { break e; }
        };

        if err != 0 {
            if permit_failure != 0 {
                eup_len = 0;
                egp_len = 0;
            } else {
                idvec_free((*new).uids);
                idvec_free((*new).gids);
                libc::free(new as *mut c_void);
                if !user.is_null() { *user = std::ptr::null_mut(); }
                return err;
            }
        }

        err = idvec_set_ids((*new).uids, eup, eup_len);
        if err == 0 { err = idvec_set_ids((*new).gids, egp, egp_len); }

        if err != 0 {
            idvec_free((*new).uids);
            idvec_free((*new).gids);
            libc::free(new as *mut c_void);
            if !user.is_null() { *user = std::ptr::null_mut(); }
            return err;
        }

        if !user.is_null() { *user = new; }
        0
    }
}