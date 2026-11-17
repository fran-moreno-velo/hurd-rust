//===========================================================================//
// crate::gnuhurd::idvec                                                     //
//---------------------------------------------------------------------------//
// From hurd libshouldbeinlibc/idvec.h  (instalada como <idvec.h>)           //
//===========================================================================//
// Enlaza las funciones de C de libshouldbeinlibc.  Todas reservan con
// malloc/realloc, así que un idvec creado aquí es compatible con el C
// (libiohelp, libfshelp...).  Las funciones "extern inline" de la cabecera
// (idvec_clear, idvec_is_empty, idvec_equal, idvec_contains) también se
// compilan dentro de la librería (IDVEC_DEFINE_EI).
//
// OJO: idvec_free e idvec_free_contents NO admiten NULL.

use libc::uid_t;
use std::ffi::{c_char, c_int, c_uint, c_void};
use crate::gnuhurd::types::auth_t;
use crate::gnumach::error::{mach_error_t, ENOMEM};

#[repr(C)]
#[derive(Debug)]
pub struct idvec {
    pub ids: *mut uid_t,
    pub num: c_uint,
    pub alloced: c_uint,
}

/// Equivalente a IDVEC_INIT.
pub const IDVEC_INIT: idvec = idvec { ids: std::ptr::null_mut(), num: 0, alloced: 0 };

pub type idvec_getpass_fn_t = Option<unsafe extern "C" fn(
    prompt: *const c_char, id: uid_t, is_group: c_int,
    pwd_or_grp: *mut c_void, hook: *mut c_void) -> *mut c_char>;

pub type idvec_verify_fn_t = Option<unsafe extern "C" fn(
    password: *const c_char, id: uid_t, is_group: c_int,
    pwd_or_grp: *mut c_void, hook: *mut c_void) -> mach_error_t>;

#[link(name = "shouldbeinlibc")]
unsafe extern "C" {
    pub fn make_idvec() -> *mut idvec;
    pub fn idvec_free_contents(idvec: *mut idvec);
    pub fn idvec_free_wrapper(idvec: *mut idvec);
    pub fn idvec_free(idvec: *mut idvec);
    pub fn idvec_clear(idvec: *mut idvec);
    pub fn idvec_is_empty(idvec: *const idvec) -> c_int;
    pub fn idvec_equal(idvec1: *const idvec, idvec2: *const idvec) -> c_int;
    pub fn idvec_ensure(idvec: *mut idvec, num: c_uint) -> mach_error_t;
    pub fn idvec_grow(idvec: *mut idvec, inc: c_uint) -> mach_error_t;
    pub fn idvec_tail_contains(idvec: *const idvec, pos: c_uint, id: uid_t) -> c_int;
    pub fn idvec_contains(idvec: *const idvec, id: uid_t) -> c_int;
    pub fn idvec_insert(idvec: *mut idvec, pos: c_uint, id: uid_t) -> mach_error_t;
    pub fn idvec_add(idvec: *mut idvec, id: uid_t) -> mach_error_t;
    pub fn idvec_add_new(idvec: *mut idvec, id: uid_t) -> mach_error_t;
    pub fn idvec_insert_new(idvec: *mut idvec, pos: c_uint, id: uid_t) -> mach_error_t;
    pub fn idvec_set_ids(idvec: *mut idvec, ids: *const uid_t, num: c_uint) -> mach_error_t;
    pub fn idvec_set(idvec: *mut idvec, new: *const idvec) -> mach_error_t;
    pub fn idvec_merge_ids(idvec: *mut idvec, ids: *const uid_t, num: c_uint) -> mach_error_t;
    pub fn idvec_merge(idvec: *mut idvec, new: *const idvec) -> mach_error_t;
    pub fn idvec_subtract(idvec: *mut idvec, sub: *const idvec) -> c_int;
    pub fn idvec_keep(idvec: *mut idvec, keep: *const idvec) -> c_int;
    pub fn idvec_remove(idvec: *mut idvec, pos: c_uint, id: uid_t) -> c_int;
    pub fn idvec_delete(idvec: *mut idvec, pos: c_uint);
    pub fn idvec_insert_only(idvec: *mut idvec, pos: c_uint, id: uid_t) -> mach_error_t;
    pub fn idvec_setid(eff: *mut idvec, avail: *mut idvec, id: uid_t,
                       secure: *mut c_int) -> mach_error_t;
    pub fn idvec_merge_auth(eff_uids: *mut idvec, avail_uids: *mut idvec,
                            eff_gids: *mut idvec, avail_gids: *mut idvec,
                            auth: auth_t) -> mach_error_t;
    pub fn idvec_merge_implied_gids(gids: *mut idvec, uids: *const idvec) -> mach_error_t;
    pub fn idvec_verify(uids: *const idvec, gids: *const idvec,
                        have_uids: *const idvec, have_gids: *const idvec,
                        getpass_fn: idvec_getpass_fn_t, getpass_hook: *mut c_void,
                        verify_fn: idvec_verify_fn_t, verify_hook: *mut c_void)
        -> mach_error_t;
    /// Devuelve una cadena reservada con malloc (liberar con libc::free).
    pub fn idvec_rep(idvec: *const idvec, show_values: c_int, show_names: c_int,
                     id_name_fn: Option<unsafe extern "C" fn(id: uid_t) -> *mut c_char>,
                     sep: *const c_char) -> *mut c_char;
    pub fn idvec_uids_rep(idvec: *const idvec, show_values: c_int, show_names: c_int,
                          sep: *const c_char) -> *mut c_char;
    pub fn idvec_gids_rep(idvec: *const idvec, show_values: c_int, show_names: c_int,
                          sep: *const c_char) -> *mut c_char;
}

/// Alias de C: #define idvec_fini idvec_free_contents.
pub use idvec_free_contents as idvec_fini;

//---------------------------------------------------------------------------//
// Envoltura segura: un idvec propio que se libera al destruirse             //
//---------------------------------------------------------------------------//

pub struct IdVec(*mut idvec);

#[inline]
fn kr(err: mach_error_t) -> Result<(), mach_error_t> {
    if err == 0 { Ok(()) } else { Err(err) }
}

impl IdVec {
    pub fn new() -> Result<IdVec, mach_error_t> {
        let p = unsafe { make_idvec() };
        if p.is_null() { Err(ENOMEM) } else { Ok(IdVec(p)) }
    }

    pub fn from_ids(ids: &[uid_t]) -> Result<IdVec, mach_error_t> {
        let v = IdVec::new()?;
        kr(unsafe { idvec_set_ids(v.0, ids.as_ptr(), ids.len() as c_uint) })?;
        Ok(v)
    }

    pub fn as_slice(&self) -> &[uid_t] {
        let v = unsafe { &*self.0 };
        if v.ids.is_null() || v.num == 0 { &[] }
        else { unsafe { std::slice::from_raw_parts(v.ids, v.num as usize) } }
    }

    pub fn len(&self) -> usize { unsafe { (*self.0).num as usize } }
    pub fn is_empty(&self) -> bool { self.len() == 0 }

    pub fn contains(&self, id: uid_t) -> bool {
        self.as_slice().contains(&id)
    }

    pub fn add(&mut self, id: uid_t) -> Result<(), mach_error_t> {
        kr(unsafe { idvec_add(self.0, id) })
    }

    pub fn add_new(&mut self, id: uid_t) -> Result<(), mach_error_t> {
        kr(unsafe { idvec_add_new(self.0, id) })
    }

    pub fn merge(&mut self, other: &IdVec) -> Result<(), mach_error_t> {
        kr(unsafe { idvec_merge(self.0, other.0) })
    }

    pub fn clear(&mut self) { unsafe { (*self.0).num = 0; } }

    /// Puntero para pasar a funciones de C (sigue perteneciendo a este IdVec).
    pub fn as_ptr(&self) -> *mut idvec { self.0 }

    /// Cede el idvec a C (por ejemplo a iohelp_create_iouser), que lo liberará.
    pub fn into_raw(self) -> *mut idvec {
        let p = self.0;
        std::mem::forget(self);
        p
    }
}

impl Drop for IdVec {
    fn drop(&mut self) {
        unsafe { idvec_free(self.0); }
    }
}
