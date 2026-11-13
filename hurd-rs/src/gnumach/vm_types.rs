//===========================================================================//
// crate::gnumach::vm_types                                                  //
//---------------------------------------------------------------------------//
// From gnumach-1.8+git20250304                                              //
// /machine/include/mach/machine/vm_types.h                                  //
//===========================================================================//

use std::ffi::{c_int, c_uint, c_long, c_ulong, c_ulonglong};

pub type natural_t = c_uint;
pub type integer_t = c_int;

pub type long_natural_t = c_ulong;
pub type long_integer_t = c_long;

pub type vm_offset_t = usize;
pub type vm_offset_array_t = *mut vm_offset_t;

pub type vm_address_t = vm_offset_t;
pub type pointer_t = vm_offset_t;

pub type phys_addr_t = c_ulonglong;

pub type rpc_phys_addr_t = c_ulonglong;
pub type rpc_phys_addr_array_t = *mut rpc_phys_addr_t;

pub type vm_size_t = usize;
pub type vm_size_array_t = *mut vm_size_t;

pub type rpc_uintptr_t = usize;
pub type rpc_vm_address_t = vm_offset_t;
pub type rpc_vm_offset_t = vm_offset_t;
pub type rpc_vm_size_t = vm_size_t;

pub type rpc_long_natural_t = long_natural_t;
pub type rpc_long_integer_t = long_integer_t;
