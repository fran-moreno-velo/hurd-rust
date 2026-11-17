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



//---------------------------------------------------------------------------//
// Iteración (equivalente a HURD_IHASH_ITERATE / HURD_IHASH_ITERATE_ITEMS)   //
//---------------------------------------------------------------------------//
// En ihash.h una ranura libre vale _HURD_IHASH_EMPTY (NULL) y una borrada
// _HURD_IHASH_DELETED ((void *) -1); las macros de iteración las saltan.

pub const _HURD_IHASH_EMPTY: hurd_ihash_value_t = std::ptr::null_mut();
pub const _HURD_IHASH_DELETED: hurd_ihash_value_t = usize::MAX as hurd_ihash_value_t;

/// Equivalente a hurd_ihash_value_valid (inline en ihash.h).
#[inline]
pub fn hurd_ihash_value_valid(value: hurd_ihash_value_t) -> bool {
    value != _HURD_IHASH_EMPTY && value != _HURD_IHASH_DELETED
}

/// Iterador sobre los pares (clave, valor) válidos de una tabla.
pub struct HurdIhashIter<'a> {
    items: *const _hurd_ihash_item,
    size: usize,
    idx: usize,
    _table: std::marker::PhantomData<&'a hurd_ihash>,
}

impl Iterator for HurdIhashIter<'_> {
    type Item = (hurd_ihash_key_t, hurd_ihash_value_t);

    fn next(&mut self) -> Option<Self::Item> {
        while self.idx < self.size {
            let item = unsafe { &*self.items.add(self.idx) };
            self.idx += 1;
            if hurd_ihash_value_valid(item.value) {
                return Some((item.key, item.value));
            }
        }
        None
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (0, Some(self.size - self.idx))
    }
}

impl hurd_ihash {
    /// Recorre los elementos de la tabla, como HURD_IHASH_ITERATE_ITEMS.
    ///
    /// # Safety
    /// La tabla debe estar inicializada y nadie debe modificarla mientras
    /// dure la iteración (en C, el llamante tiene el lock que la protege;
    /// por ejemplo, _ports_htable_lock para las tablas de libports).
    pub unsafe fn iter(&self) -> HurdIhashIter<'_> {
        let size = if self.items.is_null() { 0 } else { self.size };
        HurdIhashIter { items: self.items, size, idx: 0,
                        _table: std::marker::PhantomData }
    }

    /// Número de elementos válidos (campo nr_items).
    pub fn len(&self) -> usize {
        self.nr_items
    }

    pub fn is_empty(&self) -> bool {
        self.nr_items == 0
    }
}
