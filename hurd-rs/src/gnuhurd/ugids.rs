//===========================================================================//
// crate::gnuhurd::ugids                                                     //
//---------------------------------------------------------------------------//
// From hurd libshouldbeinlibc/ugids.h  (instalada como <ugids.h>)           //
//===========================================================================//
// No se incluyen ugids_argp ni struct ugids_argp_params (dependen de argp).

use libc::{gid_t, uid_t};
use std::ffi::{c_char, c_int};
use crate::gnuhurd::idvec::{idvec, idvec_getpass_fn_t, idvec_verify_fn_t, IDVEC_INIT};
use crate::gnuhurd::types::auth_t;
use crate::gnumach::error::mach_error_t;
use std::ffi::c_void;

#[repr(C)]
#[derive(Debug)]
pub struct ugids {
    pub eff_uids: idvec,        // Effective UIDs
    pub eff_gids: idvec,        // Effective GIDs
    pub avail_uids: idvec,      // Available UIDs
    pub avail_gids: idvec,      // Available GIDs
    /// Subconjuntos de eff/avail_gids implicados por los uids.
    pub imp_eff_gids: idvec,
    pub imp_avail_gids: idvec,
}

/// Equivalente a UGIDS_INIT.
pub const UGIDS_INIT: ugids = ugids {
    eff_uids: IDVEC_INIT, eff_gids: IDVEC_INIT,
    avail_uids: IDVEC_INIT, avail_gids: IDVEC_INIT,
    imp_eff_gids: IDVEC_INIT, imp_avail_gids: IDVEC_INIT,
};

#[link(name = "shouldbeinlibc")]
unsafe extern "C" {
    pub fn make_ugids() -> *mut ugids;
    pub fn ugids_fini(ugids: *mut ugids);
    pub fn ugids_free(ugids: *mut ugids);
    pub fn ugids_is_empty(ugids: *const ugids) -> c_int;
    pub fn ugids_equal(ugids1: *const ugids, ugids2: *const ugids) -> c_int;
    pub fn ugids_merge(ugids: *mut ugids, new: *const ugids) -> mach_error_t;
    pub fn ugids_set(ugids: *mut ugids, new: *const ugids) -> mach_error_t;
    pub fn ugids_subtract(ugids: *mut ugids, sub: *const ugids) -> mach_error_t;
    pub fn ugids_imply_all(ugids: *mut ugids) -> mach_error_t;
    pub fn ugids_save(ugids: *mut ugids) -> mach_error_t;
    pub fn ugids_verify(ugids: *const ugids, have_uids: *const idvec, have_gids: *const idvec,
                        getpass_fn: idvec_getpass_fn_t, getpass_hook: *mut c_void,
                        verify_fn: idvec_verify_fn_t, verify_hook: *mut c_void)
        -> mach_error_t;
    pub fn ugids_make_auth(ugids: *const ugids, from: *const auth_t, num_from: usize,
                           auth: *mut auth_t) -> mach_error_t;
    pub fn ugids_verify_make_auth(ugids: *const ugids,
                                  have_uids: *const idvec, have_gids: *const idvec,
                                  getpass_fn: idvec_getpass_fn_t, getpass_hook: *mut c_void,
                                  from: *const auth_t, num_from: usize,
                                  auth: *mut auth_t) -> mach_error_t;
    pub fn ugids_merge_auth(ugids: *mut ugids, auth: auth_t) -> mach_error_t;
    /// Devuelve una cadena reservada con malloc (liberar con libc::free).
    pub fn ugids_rep(ugids: *const ugids, show_values: c_int, show_names: c_int,
                     id_sep: *const c_char, type_sep: *const c_char,
                     hdr_sep: *const c_char) -> *mut c_char;
    pub fn ugids_add_uid(ugids: *mut ugids, uid: uid_t, avail: c_int) -> mach_error_t;
    pub fn ugids_add_gid(ugids: *mut ugids, gid: gid_t, avail: c_int) -> mach_error_t;
    pub fn ugids_add_user(ugids: *mut ugids, uid: uid_t, avail: c_int) -> mach_error_t;
    pub fn ugids_set_posix_user(ugids: *mut ugids, uid: uid_t) -> mach_error_t;
}
