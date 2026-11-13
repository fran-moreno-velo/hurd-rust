//===========================================================================//
// crate::gnumach::vm_inherit                                                //
//---------------------------------------------------------------------------//
// From gnumach                                                              //
// include/mach/vm_inherit.h                                                 //
//===========================================================================//

use std::ffi::c_int;

pub type vm_inherit_t = c_int;

pub const VM_INHERIT_SHARE: vm_inherit_t   = 0;  // share with child
pub const VM_INHERIT_COPY: vm_inherit_t    = 1;  // copy into child
pub const VM_INHERIT_NONE: vm_inherit_t    = 2;  // absent from child
pub const VM_INHERIT_DEFAULT: vm_inherit_t = VM_INHERIT_COPY;
