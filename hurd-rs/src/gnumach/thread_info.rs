//===========================================================================//
// crate::gnumach::thread_info                                               //
//---------------------------------------------------------------------------//
// From gnumach                                                              //
// include/mach/thread_info.h                                                //
//===========================================================================//

use crate::gnumach::message::mach_msg_type_number_t;
use crate::gnumach::time_value::{rpc_time_value_t, time_value64_t};
use crate::gnumach::vm_types::{integer_t, natural_t};
use std::mem::size_of;

pub type thread_info_t = *mut integer_t;         // varying array of ints
pub const THREAD_INFO_MAX: usize = 1024;         // maximum array size
pub type thread_info_data_t = [integer_t; THREAD_INFO_MAX];

pub type thread_flavor_t = integer_t;

//---------------------------------------------------------------------------//
// THREAD_BASIC_INFO                                                         //
//---------------------------------------------------------------------------//

pub const THREAD_BASIC_INFO: thread_flavor_t = 1;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct thread_basic_info_data_t {
    /// Obsoleto: usar user_time64.
    pub user_time: rpc_time_value_t,        // user run time
    /// Obsoleto: usar system_time64.
    pub system_time: rpc_time_value_t,      // system run time
    pub cpu_usage: integer_t,               // scaled cpu usage percentage
    pub base_priority: integer_t,           // base scheduling priority
    pub cur_priority: integer_t,            // current scheduling priority
    pub run_state: integer_t,               // run state (TH_STATE_*)
    pub flags: integer_t,                   // various flags (TH_FLAGS_*)
    pub suspend_count: integer_t,           // suspend count for thread
    pub sleep_time: integer_t,              // seconds the thread has been sleeping
    /// Obsoleto: usar creation_time64.
    pub creation_time: rpc_time_value_t,    // time stamp of creation
    pub user_time64: time_value64_t,
    pub system_time64: time_value64_t,
    pub creation_time64: time_value64_t,
}
pub type thread_basic_info_t = *mut thread_basic_info_data_t;
// En C se divide por sizeof(natural_t), no por sizeof(integer_t): mismo tamaño.
pub const THREAD_BASIC_INFO_COUNT: mach_msg_type_number_t =
    (size_of::<thread_basic_info_data_t>() / size_of::<natural_t>()) as mach_msg_type_number_t;

/// Escala del campo cpu_usage.
pub const TH_USAGE_SCALE: integer_t = 1000;

// Estados (campo run_state).
pub const TH_STATE_RUNNING: integer_t         = 1; // running normally
pub const TH_STATE_STOPPED: integer_t         = 2; // stopped
pub const TH_STATE_WAITING: integer_t         = 3; // waiting normally
pub const TH_STATE_UNINTERRUPTIBLE: integer_t = 4; // uninterruptible wait
pub const TH_STATE_HALTED: integer_t          = 5; // halted at a clean point

// Flags (campo flags).
pub const TH_FLAGS_SWAPPED: integer_t = 0x1;       // swapped out
pub const TH_FLAGS_IDLE: integer_t    = 0x2;       // idle thread

//---------------------------------------------------------------------------//
// THREAD_SCHED_INFO                                                         //
//---------------------------------------------------------------------------//

pub const THREAD_SCHED_INFO: thread_flavor_t = 2;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct thread_sched_info_data_t {
    pub policy: integer_t,           // scheduling policy
    pub data: integer_t,             // associated data
    pub base_priority: integer_t,    // base priority
    pub max_priority: integer_t,     // max priority
    pub cur_priority: integer_t,     // current priority
    pub depressed: integer_t,        // depressed? (boolean_t en C)
    pub depress_priority: integer_t, // priority depressed from
    pub last_processor: integer_t,   // last processor used by the thread
}
pub type thread_sched_info_t = *mut thread_sched_info_data_t;
pub const THREAD_SCHED_INFO_COUNT: mach_msg_type_number_t =
    (size_of::<thread_sched_info_data_t>() / size_of::<natural_t>()) as mach_msg_type_number_t;
