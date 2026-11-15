//===========================================================================//
// crate::gnumach::thread                                                    //
//---------------------------------------------------------------------------//
// From gnumach-1.8+git20250304                                              //
// include/mach/mach.defs  (rutinas thread_*)                                //
// include/mach/thread_special_ports.h  (VERIFICAR)                          //
//===========================================================================//

use crate::gnumach::kern_return::kern_return_t;
use crate::gnumach::mach_types::{task_t, thread_t};
use crate::gnumach::message::mach_msg_type_number_t;
use crate::gnumach::port::{mach_port_t, MACH_PORT_NULL};
use crate::gnumach::thread_info::*;
use crate::gnumach::vm_types::{integer_t, natural_t};
use std::ffi::c_int;

/// Estado de registros dependiente de la arquitectura (array de natural_t).
pub type thread_state_t = *mut natural_t;
pub type thread_state_flavor_t = c_int;

unsafe extern "C" {
  /// *child_thread recibe un derecho de envío nuevo; el hilo nace suspendido
  /// y con estado indefinido (hay que fijarlo con thread_set_state).
  pub fn thread_create(parent_task: task_t,
                       child_thread: *mut thread_t) -> kern_return_t;

  pub fn thread_terminate(target_thread: thread_t) -> kern_return_t;

  /// *old_state_cnt: entrada = capacidad (en natural_t), salida = devueltos.
  pub fn thread_get_state(target_thread: thread_t,
                          flavor: thread_state_flavor_t,
                          old_state: thread_state_t,
                          old_state_cnt: *mut mach_msg_type_number_t) -> kern_return_t;

  pub fn thread_set_state(target_thread: thread_t,
                          flavor: thread_state_flavor_t,
                          new_state: thread_state_t,
                          new_state_cnt: mach_msg_type_number_t) -> kern_return_t;

  /// *thread_info_out_cnt: entrada = capacidad (en integer_t), salida = devueltos.
  pub fn thread_info(target_thread: thread_t,
                     flavor: thread_flavor_t,
                     thread_info_out: thread_info_t,
                     thread_info_out_cnt: *mut mach_msg_type_number_t) -> kern_return_t;

  pub fn thread_suspend(target_thread: thread_t) -> kern_return_t;
  pub fn thread_resume(target_thread: thread_t) -> kern_return_t;
  pub fn thread_abort(target_thread: thread_t) -> kern_return_t;

  pub fn thread_get_special_port(thread: thread_t,
                                 which_port: c_int,
                                 special_port: *mut mach_port_t) -> kern_return_t;
  pub fn thread_set_special_port(thread: thread_t,
                                 which_port: c_int,
                                 special_port: mach_port_t) -> kern_return_t;
}

//---------------------------------------------------------------------------//
// Special ports (thread_special_ports.h)  -- VERIFICAR valores              //
//---------------------------------------------------------------------------//

pub const THREAD_KERNEL_PORT: c_int    = 1;
pub const THREAD_EXCEPTION_PORT: c_int = 3;

//---------------------------------------------------------------------------//
// Safe wrappers                                                             //
//---------------------------------------------------------------------------//

#[inline]
fn kr(err: kern_return_t) -> Result<(), kern_return_t> {
    if err == 0 { Ok(()) } else { Err(err) }
}

fn thread_info_as<T: Default>(thread: thread_t, flavor: thread_flavor_t)
    -> Result<T, kern_return_t>
{
    let mut data = T::default();
    let mut cnt = (size_of::<T>() / size_of::<integer_t>()) as mach_msg_type_number_t;
    kr(unsafe { thread_info(thread, flavor, &mut data as *mut T as thread_info_t, &mut cnt) })?;
    Ok(data)
}

pub fn thread_basic_info(thread: thread_t) -> Result<thread_basic_info_data_t, kern_return_t> {
    thread_info_as(thread, THREAD_BASIC_INFO)
}
pub fn thread_sched_info(thread: thread_t) -> Result<thread_sched_info_data_t, kern_return_t> {
    thread_info_as(thread, THREAD_SCHED_INFO)
}

pub fn thread_get_exception_port(thread: thread_t) -> Result<mach_port_t, kern_return_t> {
    let mut port = MACH_PORT_NULL;
    kr(unsafe { thread_get_special_port(thread, THREAD_EXCEPTION_PORT, &mut port) })?;
    Ok(port)
}

pub fn thread_suspend_checked(thread: thread_t) -> Result<(), kern_return_t> {
    kr(unsafe { thread_suspend(thread) })
}
pub fn thread_resume_checked(thread: thread_t) -> Result<(), kern_return_t> {
    kr(unsafe { thread_resume(thread) })
}
pub fn thread_abort_checked(thread: thread_t) -> Result<(), kern_return_t> {
    kr(unsafe { thread_abort(thread) })
}
