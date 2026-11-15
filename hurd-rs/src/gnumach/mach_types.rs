//===========================================================================//
// crate::gnumach::mach_types                                                //
//---------------------------------------------------------------------------//
// From gnumach-1.8+git20250304                                              //
// include/mach/mach_types.h                                                 //
//===========================================================================//

use crate::gnumach::port::mach_port_t;
use crate::gnumach::vm_types::vm_offset_t;

pub type task_t                     = mach_port_t;
pub type task_array_t               = *mut task_t;
pub type vm_task_t                  = task_t;
pub type ipc_space_t                = task_t;
pub type thread_t                   = mach_port_t;
pub type thread_array_t             = *mut thread_t;
pub type host_t                     = mach_port_t;
pub type host_priv_t                = mach_port_t;
pub type processor_t                = mach_port_t;
pub type processor_array_t          = *mut mach_port_t;
pub type processor_set_t            = mach_port_t;
pub type processor_set_name_t       = mach_port_t;
pub type processor_set_array_t      = *mut mach_port_t;
pub type processor_set_name_array_t = *mut mach_port_t;
pub type emulation_vector_t         = *mut vm_offset_t;
pub type memory_object_t            = mach_port_t;
pub type memory_object_name_t       = mach_port_t;
pub type mach_port_array_t          = *mut mach_port_t;
