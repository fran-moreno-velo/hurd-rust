//===========================================================================//
// crate::gnuhurd::ihash                                                     //
//---------------------------------------------------------------------------//
// From github - gnuhurd                                                     //
// libihash/ihash.h                                                          //
//===========================================================================//

use crate::gnumach::error::mach_error_t;
use std::ffi::{c_int, c_uint, c_void};

//---------------------------------------------------------------------------//
// Extern functions                                                          //
//---------------------------------------------------------------------------//

unsafe extern "C" {
  pub fn hurd_ihash_init(
        ht: hurd_ihash_t, 
        locp_offs: isize
    );

  pub fn hurd_ihash_destroy(ht: hurd_ihash_t);

  pub fn hurd_ihash_create(
        ht: *mut hurd_ihash_t, 
        locp_offs: isize
    ) -> mach_error_t;

  pub fn hurd_ihash_free(ht: hurd_ihash_t);

  pub fn hurd_ihash_set_cleanup(
        ht: hurd_ihash_t,
        cleanup: hurd_ihash_cleanup_t,
        cleanup_data: *mut c_void,
    );

  pub fn hurd_ihash_set_gki(
        ht: hurd_ihash_t,
        fct_hash: hurd_ihash_fct_hash_t,
        fct_cmp: hurd_ihash_fct_cmp_t,
    );

  pub fn hurd_ihash_set_max_load(
        ht: hurd_ihash_t, 
        max_load: c_uint
    );

  pub fn hurd_ihash_add(
        ht: hurd_ihash_t,
        key: hurd_ihash_key_t,
        item: hurd_ihash_value_t,
    ) -> mach_error_t;

  pub fn hurd_ihash_locp_add(
        ht: hurd_ihash_t,
        locp: hurd_ihash_locp_t,
        key: hurd_ihash_key_t,
        value: hurd_ihash_value_t,
    ) -> mach_error_t;

  pub fn hurd_ihash_find(
        ht: hurd_ihash_t, 
        key: hurd_ihash_key_t
    ) -> hurd_ihash_value_t;

  pub fn hurd_ihash_locp_find(
        ht: hurd_ihash_t,
        key: hurd_ihash_key_t,
        slot: *mut hurd_ihash_locp_t,
    ) -> hurd_ihash_value_t;

  pub fn hurd_ihash_remove(
        ht: hurd_ihash_t, 
        key: hurd_ihash_key_t
    ) -> c_int;

  pub fn hurd_ihash_locp_remove(
        ht: hurd_ihash_t, 
        locp: hurd_ihash_locp_t
    );

  pub fn hurd_ihash_hash32(
        buf: *const c_void, 
        len: usize, 
        seed: u32
    ) -> u32;

}

//---------------------------------------------------------------------------//
// Public types                                                              //
//---------------------------------------------------------------------------//

pub type hurd_ihash_value_t = *mut c_void;
pub type hurd_ihash_key_t = usize;
pub type hurd_ihash_locp_t = *mut hurd_ihash_value_t;

pub type hurd_ihash_fct_hash_t = 
     Option<unsafe extern "C" fn(arg1: *const c_void) -> hurd_ihash_key_t>;

pub type hurd_ihash_fct_cmp_t = 
     Option<unsafe extern "C" fn(arg1: *const c_void, arg2: *const c_void)-> c_int>;

pub type hurd_ihash_cleanup_t = 
     Option<unsafe extern "C" fn(value: hurd_ihash_value_t, arg: *mut c_void)>;
#[repr(C)]
#[derive(Copy, Clone)]
pub struct _hurd_ihash_item {
    pub value: hurd_ihash_value_t,
    pub key: hurd_ihash_key_t,
}
pub type _hurd_ihash_item_t = *mut _hurd_ihash_item;

#[repr(C)]
pub struct hurd_ihash {
    pub nr_items: usize,
    pub items: _hurd_ihash_item_t,
    pub size: usize,
    pub locp_offset: isize,
    pub max_load: c_uint,
    pub cleanup: hurd_ihash_cleanup_t,
    pub cleanup_data: *mut c_void,
    pub fct_hash: hurd_ihash_fct_hash_t,
    pub fct_cmp: hurd_ihash_fct_cmp_t,
    pub nr_free: usize
}
pub type hurd_ihash_t = *mut hurd_ihash;

//---------------------------------------------------------------------------//
// Public constants                                                          //
//---------------------------------------------------------------------------//

pub const HURD_IHASH_MIN_SIZE: u32 = 32;
pub const HURD_IHASH_MAX_LOAD_DEFAULT: u32 = 96;
pub const HURD_IHASH_NO_LOCP: isize = isize::MIN;


