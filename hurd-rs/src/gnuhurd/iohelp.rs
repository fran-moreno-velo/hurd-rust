//===========================================================================//
// crate::gnuhurd::iohelp                                                    //
//---------------------------------------------------------------------------//
// From hurd libiohelp/iohelp.h  (instalada como <hurd/iohelp.h>)            //
//===========================================================================//
// Reimplementación en Rust de la parte de identificación de usuarios de
// libiohelp.  Las funciones llevan #[unsafe(no_mangle)]: si el proceso
// enlaza también la libiohelp de C (por ejemplo a través de libfshelp),
// estas sustituyen a las de C en todo el proceso.  Todas reservan con
// malloc/free, así que son compatibles con las de C.
// No incluye la parte de "conch" (necesita struct shared_io de <hurd/shared.h>).

use libc::{gid_t, uid_t};
use std::ffi::{c_char, c_int, c_uint, c_void};
use std::mem::size_of;
use std::ptr;
use crate::gnuhurd::idvec::{idvec, idvec_add, idvec_contains, idvec_free, idvec_set,
                            idvec_set_ids, make_idvec};
use crate::gnumach::error::{mach_error_t, ENOMEM, ENULLPTR, EOVERFLOW};
use crate::gnumach::message::mach_msg_type_number_t;
use crate::gnumach::port::mach_port_t;

//---------------------------------------------------------------------------//
// Structs                                                                   //
//---------------------------------------------------------------------------//
#[repr(C)]
#[derive(Copy, Clone)]
pub struct iouser {
    pub uids: *mut idvec,
    pub gids: *mut idvec,
    pub hook: *mut c_void,
}

//---------------------------------------------------------------------------//
// Functions                                                                 //
//---------------------------------------------------------------------------//

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
        if !i.uids.is_null() { idvec_free(i.uids); }
        if !i.gids.is_null() { idvec_free(i.gids); }
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
            unsafe { libc::free(buf as *mut c_void); }   // len > 0 aquí
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
    // Contrato de iohelp.h: "If LEN > 0, BUF is freed, regardless of whether
    // an error is returned or not."  Con LEN == 0 el buffer no es nuestro.
    if len > 0 {
        unsafe { libc::free(buf as *mut c_void); }
    }
    err
}

/// iohelp_create_complex_iouser (libiohelp/iouser-create.c): build an iouser
/// from the given uids/gids arrays.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn iohelp_create_complex_iouser(
    user: *mut *mut iouser,
    uvec: *const uid_t,
    nuids: c_int,
    gvec: *const gid_t,
    ngids: c_int,
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
        let mut err = idvec_set_ids(uids, uvec, nuids as c_uint);
        if err == 0 { err = idvec_set_ids(gids, gvec, ngids as c_uint); }
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

/// iohelp_create_simple_iouser (libiohelp): iouser con un solo uid y gid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn iohelp_create_simple_iouser(
    user: *mut *mut iouser,
    uid: uid_t,
    gid: gid_t,
) -> mach_error_t {
    unsafe { iohelp_create_complex_iouser(user, &uid, 1, &gid, 1) }
}

/// iohelp_create_empty_iouser (libiohelp): iouser sin identidad.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn iohelp_create_empty_iouser(user: *mut *mut iouser) -> mach_error_t {
    unsafe { iohelp_create_complex_iouser(user, ptr::null(), 0, ptr::null(), 0) }
}

/// iohelp_restrict_iouser (libiohelp/iouser-restrict.c): nuevo iouser que
/// restringe OLD_USER a los ids pedidos (para implementar io_restrict_auth).
/// Si OLD_USER es root (uid 0) puede usar cualquier id; si no, solo los que
/// ya tenía de entre los pedidos.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn iohelp_restrict_iouser(
    new_user: *mut *mut iouser,
    old_user: *const iouser,
    uids: *const uid_t,
    nuids: c_int,
    gids: *const gid_t,
    ngids: c_int,
) -> mach_error_t {
    unsafe {
        if !new_user.is_null() { *new_user = ptr::null_mut(); }
        if old_user.is_null() { return ENULLPTR; }
        let old = &*old_user;

        if idvec_contains(old.uids, 0) != 0 {
            return iohelp_create_complex_iouser(new_user, uids, nuids, gids, ngids);
        }

        let as_slice = |p: *const uid_t, n: c_int| -> &[uid_t] {
            if p.is_null() || n <= 0 { &[] } else { std::slice::from_raw_parts(p, n as usize) }
        };
        let want_u = as_slice(uids, nuids);
        let want_g = as_slice(gids, ngids);

        let uvec = make_idvec();
        if uvec.is_null() { return ENOMEM; }
        let gvec = make_idvec();
        if gvec.is_null() { idvec_free(uvec); return ENOMEM; }

        let mut err = 0;
        for &id in as_slice((*old.uids).ids, (*old.uids).num as c_int) {
            if err == 0 && want_u.contains(&id) { err = idvec_add(uvec, id); }
        }
        for &id in as_slice((*old.gids).ids, (*old.gids).num as c_int) {
            if err == 0 && want_g.contains(&id) { err = idvec_add(gvec, id); }
        }
        if err == 0 {
            err = iohelp_create_iouser(new_user, uvec, gvec);
        }
        if err != 0 {
            idvec_free(uvec);
            idvec_free(gvec);
        }
        err
    }
}

/// iohelp_reauth (libiohelp/iouser-reauth.c): conduct a reauthentication
/// transaction against AUTHSERVER, returning a new iouser in *USER.
/// REND_PORT is the rendezvous port, NEWRIGHT the new right to hand the user.
/// If PERMIT_FAILURE is nonzero and the transaction fails, *USER gets an
/// iouser without ids (same behaviour as the C version).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn iohelp_reauth(
    user: *mut *mut iouser,
    authserver: mach_port_t,
    rend_port: mach_port_t,
    newright: mach_port_t,
    permit_failure: c_int,
) -> mach_error_t {
    use crate::gnuhurd::auth::auth_server_authenticate;
    use crate::gnumach::error::EINTR;
    use crate::gnumach::message::MACH_MSG_TYPE_COPY_SEND;

    /// Si MIG devolvió el array fuera de línea (otro buffer distinto del nuestro),
    /// esa memoria la reservó el núcleo en nuestro espacio: hay que liberarla.
    unsafe fn free_if_ool(p: *mut uid_t, local: *mut uid_t, n: mach_msg_type_number_t) {
        if p != local && !p.is_null() && n > 0 {
            unsafe { libc::munmap(p as *mut c_void, n as usize * size_of::<uid_t>()); }
        }
    }

    const BUFN: usize = 20;
    unsafe {
        if !user.is_null() { *user = ptr::null_mut(); }

        let uids = make_idvec();
        let gids = make_idvec();
        let new = if uids.is_null() || gids.is_null() {
            ptr::null_mut()
        } else {
            iouser_new(uids, gids)
        };
        if new.is_null() {
            if !uids.is_null() { idvec_free(uids); }   // idvec_free (C) no admite NULL
            if !gids.is_null() { idvec_free(gids); }
            return ENOMEM;
        }

        // Buffers locales: MIG escribe en ellos si los ids caben (<= 20).
        let mut gubuf = [0 as uid_t; BUFN];
        let mut ggbuf = [0 as uid_t; BUFN];
        let mut aubuf = [0 as uid_t; BUFN];
        let mut agbuf = [0 as uid_t; BUFN];
        let mut gen_uids = gubuf.as_mut_ptr();
        let mut gen_gids = ggbuf.as_mut_ptr();
        let mut aux_uids = aubuf.as_mut_ptr();
        let mut aux_gids = agbuf.as_mut_ptr();
        let mut genuidlen: mach_msg_type_number_t = BUFN as mach_msg_type_number_t;
        let mut gengidlen: mach_msg_type_number_t = BUFN as mach_msg_type_number_t;
        let mut auxuidlen: mach_msg_type_number_t = BUFN as mach_msg_type_number_t;
        let mut auxgidlen: mach_msg_type_number_t = BUFN as mach_msg_type_number_t;

        let mut err = loop {
            let e = auth_server_authenticate(
                authserver,
                rend_port, MACH_MSG_TYPE_COPY_SEND,
                newright,  MACH_MSG_TYPE_COPY_SEND,
                &mut gen_uids, &mut genuidlen,
                &mut aux_uids, &mut auxuidlen,
                &mut gen_gids, &mut gengidlen,
                &mut aux_gids, &mut auxgidlen,
            );
            if e != EINTR { break e; }
        };

        if err != 0 {
            if permit_failure == 0 {
                iohelp_free_iouser(new);
                return err;
            }
            // Como en C: se sigue con un usuario sin ids.
            genuidlen = 0;
            gengidlen = 0;
        }

        err = idvec_set_ids(uids, gen_uids, genuidlen);
        if err == 0 { err = idvec_set_ids(gids, gen_gids, gengidlen); }

        // idvec_set_ids ya ha copiado los ids: liberamos lo que MIG trajo fuera de línea.
        free_if_ool(gen_uids, gubuf.as_mut_ptr(), genuidlen);
        free_if_ool(gen_gids, ggbuf.as_mut_ptr(), gengidlen);
        free_if_ool(aux_uids, aubuf.as_mut_ptr(), auxuidlen);
        free_if_ool(aux_gids, agbuf.as_mut_ptr(), auxgidlen);

        if err != 0 {
            iohelp_free_iouser(new);
            return err;
        }
        if !user.is_null() { *user = new; }
        0
    }
}

