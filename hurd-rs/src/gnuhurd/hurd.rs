//===========================================================================//
// crate::gnuhurd::hurd                                                      //
//---------------------------------------------------------------------------//
// From glibc <hurd.h>                                                       //
//===========================================================================//

use std::ffi::{c_char, c_int};
use libc::mode_t;
use crate::gnuhurd::io::file_t;

unsafe extern "C" {
    /// Abre FILE y devuelve su puerto (MACH_PORT_NULL y errno si falla).
    /// El puerto devuelto es una referencia nueva: liberarla con mach_port_deallocate.
    pub fn file_name_lookup(file: *const c_char, flags: c_int, mode: mode_t) -> file_t;
}
