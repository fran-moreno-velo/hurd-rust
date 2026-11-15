//===========================================================================//
// crate::gnumach::task_info                                                 //
//---------------------------------------------------------------------------//
// From gnumach                                                              //
// include/mach/task_info.h                                                  //
//===========================================================================//

use crate::gnumach::message::mach_msg_type_number_t;
use crate::gnumach::time_value::{rpc_time_value_t, time_value64_t};
use crate::gnumach::vm_types::{integer_t, rpc_long_natural_t, rpc_vm_size_t};
use std::mem::size_of;

pub type task_info_t = *mut integer_t;           // varying array of int
pub const TASK_INFO_MAX: usize = 1024;           // maximum array size
pub type task_info_data_t = [integer_t; TASK_INFO_MAX];

pub type task_flavor_t = integer_t;

//---------------------------------------------------------------------------//
// TASK_BASIC_INFO                                                           //
//---------------------------------------------------------------------------//

pub const TASK_BASIC_INFO: task_flavor_t = 1;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct task_basic_info_data_t {
    pub suspend_count: integer_t,           // suspend count for task
    pub base_priority: integer_t,           // base scheduling priority
    pub virtual_size: rpc_vm_size_t,        // number of virtual pages
    pub resident_size: rpc_vm_size_t,       // number of resident pages
    /// Obsoleto: usar user_time64.
    pub user_time: rpc_time_value_t,        // run time of terminated threads
    /// Obsoleto: usar system_time64.
    pub system_time: rpc_time_value_t,
    /// Obsoleto: usar creation_time64.
    pub creation_time: rpc_time_value_t,    // creation time stamp
    pub user_time64: time_value64_t,
    pub system_time64: time_value64_t,
    pub creation_time64: time_value64_t,
}
pub type task_basic_info_t = *mut task_basic_info_data_t;
pub const TASK_BASIC_INFO_COUNT: mach_msg_type_number_t =
    (size_of::<task_basic_info_data_t>() / size_of::<integer_t>()) as mach_msg_type_number_t;

//---------------------------------------------------------------------------//
// TASK_EVENTS_INFO                                                          //
//---------------------------------------------------------------------------//

pub const TASK_EVENTS_INFO: task_flavor_t = 2;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct task_events_info_data_t {
    pub faults: rpc_long_natural_t,             // number of page faults
    pub zero_fills: rpc_long_natural_t,         // number of zero fill pages
    pub reactivations: rpc_long_natural_t,      // number of reactivated pages
    pub pageins: rpc_long_natural_t,            // number of actual pageins
    pub cow_faults: rpc_long_natural_t,         // number of copy-on-write faults
    pub messages_sent: rpc_long_natural_t,      // number of messages sent
    pub messages_received: rpc_long_natural_t,  // number of messages received
}
pub type task_events_info_t = *mut task_events_info_data_t;
pub const TASK_EVENTS_INFO_COUNT: mach_msg_type_number_t =
    (size_of::<task_events_info_data_t>() / size_of::<integer_t>()) as mach_msg_type_number_t;

//---------------------------------------------------------------------------//
// TASK_THREAD_TIMES_INFO                                                    //
//---------------------------------------------------------------------------//

/// Tiempos totales de los hilos vivos (exactos solo si la tarea está suspendida).
pub const TASK_THREAD_TIMES_INFO: task_flavor_t = 3;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct task_thread_times_info_data_t {
    /// Obsoleto: usar user_time64.
    pub user_time: rpc_time_value_t,
    /// Obsoleto: usar system_time64.
    pub system_time: rpc_time_value_t,
    pub user_time64: time_value64_t,
    pub system_time64: time_value64_t,
}
pub type task_thread_times_info_t = *mut task_thread_times_info_data_t;
pub const TASK_THREAD_TIMES_INFO_COUNT: mach_msg_type_number_t =
    (size_of::<task_thread_times_info_data_t>() / size_of::<integer_t>()) as mach_msg_type_number_t;

//---------------------------------------------------------------------------//
// Flavors de task_ras_control                                               //
//---------------------------------------------------------------------------//

pub const TASK_RAS_CONTROL_PURGE_ALL: integer_t             = 0;
pub const TASK_RAS_CONTROL_PURGE_ONE: integer_t             = 1;
pub const TASK_RAS_CONTROL_PURGE_ALL_AND_INSTALL_ONE: integer_t = 2;
pub const TASK_RAS_CONTROL_INSTALL_ONE: integer_t           = 3;
