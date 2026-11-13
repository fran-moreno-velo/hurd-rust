//===========================================================================//
// crate::gnumach::boolean                                                   //
//---------------------------------------------------------------------------//
// From gnumach-1.8+git20250304                                              //
// include/mach/boolean.h                                                    //
//===========================================================================//

use std::ffi::c_int;

pub type boolean_t = c_int;

pub const MACH_BOOLEAN_FALSE: boolean_t = 0;
pub const MACH_BOOLEAN_TRUE: boolean_t  = 1;