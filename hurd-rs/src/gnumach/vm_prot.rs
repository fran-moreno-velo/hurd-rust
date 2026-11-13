//===========================================================================//
// crate::gnumach::vm_prot                                                   //
//---------------------------------------------------------------------------//
// From gnumach                                                              //
// include/mach/vm_prot.h                                                    //
//===========================================================================//

use std::ffi::c_int;

pub type vm_prot_t = c_int;

pub const VM_PROT_NONE: vm_prot_t    = 0x00;
pub const VM_PROT_READ: vm_prot_t    = 0x01;  // read permission
pub const VM_PROT_WRITE: vm_prot_t   = 0x02;  // write permission
pub const VM_PROT_EXECUTE: vm_prot_t = 0x04;  // execute permission

pub const VM_PROT_DEFAULT: vm_prot_t = VM_PROT_READ | VM_PROT_WRITE;
pub const VM_PROT_ALL: vm_prot_t     = VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE;

/// Solo para memory_object_lock_request: no cambiar la protección.
pub const VM_PROT_NO_CHANGE: vm_prot_t = 0x08;
/// Solo para memory_object_data_supply: avisar al pager en el primer acceso.
pub const VM_PROT_NOTIFY: vm_prot_t    = 0x10;
