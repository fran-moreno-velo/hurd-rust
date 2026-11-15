//===========================================================================//
// crate::gnumach::task                                                      //
//---------------------------------------------------------------------------//
// From gnumach-1.8+git20250304                                              //
// include/mach/task_special_ports.h                                         //
// include/mach/mach.defs  (rutinas task_* y mach_ports_*)                   //
//===========================================================================//

use crate::gnumach::boolean::boolean_t;
use crate::gnumach::kern_return::kern_return_t;
use crate::gnumach::mach_types::{mach_port_array_t, task_t, thread_array_t, thread_t};
use crate::gnumach::message::mach_msg_type_number_t;
use crate::gnumach::port::{mach_port_t, take_ool, MACH_PORT_NULL};
use crate::gnumach::task_info::*;
use crate::gnumach::vm_types::{integer_t, vm_address_t};
use std::ffi::c_int;


//---------------------------------------------------------------------------//
// Extern functions                                                          //
//---------------------------------------------------------------------------//

unsafe extern "C" {
  static mut __mach_task_self_: mach_port_t;

  /// *child_task recibe un derecho de envío nuevo.
  pub fn task_create(target_task: task_t,
                     inherit_memory: boolean_t,
                     child_task: *mut task_t) -> kern_return_t;

  pub fn task_terminate(target_task: task_t) -> kern_return_t;

  /// *thread_list llega fuera de línea y cada elemento es un derecho de envío:
  /// liberar los derechos con mach_port_deallocate y el array con vm_deallocate.
  pub fn task_threads(target_task: task_t,
                      thread_list: *mut thread_array_t,
                      thread_list_cnt: *mut mach_msg_type_number_t) -> kern_return_t;

  /// *task_info_out_cnt: entrada = capacidad (en integer_t), salida = devueltos.
  pub fn task_info(target_task: task_t,
                   flavor: task_flavor_t,
                   task_info_out: task_info_t,
                   task_info_out_cnt: *mut mach_msg_type_number_t) -> kern_return_t;

  pub fn task_suspend(target_task: task_t) -> kern_return_t;
  pub fn task_resume(target_task: task_t) -> kern_return_t;

  pub fn task_get_special_port(task: task_t,
                               which_port: c_int,
                               special_port: *mut mach_port_t) -> kern_return_t;
  pub fn task_set_special_port(task: task_t,
                               which_port: c_int,
                               special_port: mach_port_t) -> kern_return_t;

  pub fn task_ras_control(target_task: task_t,
                          basepc: vm_address_t,
                          boundspc: vm_address_t,
                          flavor: c_int) -> kern_return_t;

  pub fn mach_ports_register(target_task: task_t,
                             init_port_set: mach_port_array_t,
                             init_port_set_cnt: mach_msg_type_number_t) -> kern_return_t;

  /// *init_port_set llega fuera de línea (derechos de envío + array a liberar).
  pub fn mach_ports_lookup(target_task: task_t,
                           init_port_set: *mut mach_port_array_t,
                           init_port_set_cnt: *mut mach_msg_type_number_t) -> kern_return_t;
}

//---------------------------------------------------------------------------//
// mach_task_self                                                            //
//---------------------------------------------------------------------------//

/// Equivalente a la macro mach_task_self() de <mach/mach_init.h>:
/// lee la caché de glibc, sin llamada al núcleo y sin sumar referencias.
/// El nombre devuelto pertenece a glibc: no se debe liberar con mach_port_deallocate.
#[inline]
pub fn mach_task_self() -> mach_port_t {
    unsafe { core::ptr::read_volatile(&raw const __mach_task_self_) }
}

//---------------------------------------------------------------------------//
// Special ports (task_special_ports.h)                                      //
//---------------------------------------------------------------------------//

pub const TASK_KERNEL_PORT: c_int    = 1;
pub const TASK_EXCEPTION_PORT: c_int = 3;
pub const TASK_BOOTSTRAP_PORT: c_int = 4;

fn task_get_port(task: task_t, which: c_int) -> Result<mach_port_t, kern_return_t> {
    let mut port: mach_port_t = MACH_PORT_NULL;
    let err = unsafe { task_get_special_port(task, which, &mut port) };
    if err == 0 { Ok(port) } else { Err(err) }
}

pub fn task_get_kernel_port(task: task_t) -> Result<mach_port_t, kern_return_t> {
    task_get_port(task, TASK_KERNEL_PORT)
}
pub fn task_get_exception_port(task: task_t) -> Result<mach_port_t, kern_return_t> {
    task_get_port(task, TASK_EXCEPTION_PORT)
}
pub fn task_get_bootstrap_port(task: task_t) -> Result<mach_port_t, kern_return_t> {
    task_get_port(task, TASK_BOOTSTRAP_PORT)
}

pub fn task_set_kernel_port(task: task_t, port: mach_port_t) -> kern_return_t {
    unsafe { task_set_special_port(task, TASK_KERNEL_PORT, port) }
}
pub fn task_set_exception_port(task: task_t, port: mach_port_t) -> kern_return_t {
    unsafe { task_set_special_port(task, TASK_EXCEPTION_PORT, port) }
}
pub fn task_set_bootstrap_port(task: task_t, port: mach_port_t) -> kern_return_t {
    unsafe { task_set_special_port(task, TASK_BOOTSTRAP_PORT, port) }
}

//---------------------------------------------------------------------------//
// Safe wrappers                                                             //
//---------------------------------------------------------------------------//

#[inline]
fn kr(err: kern_return_t) -> Result<(), kern_return_t> {
    if err == 0 { Ok(()) } else { Err(err) }
}

/// Lee una estructura de información con un flavor de task_info.
fn task_info_as<T: Default>(task: task_t, flavor: task_flavor_t)
    -> Result<T, kern_return_t>
{
    let mut data = T::default();
    let mut cnt = (size_of::<T>() / size_of::<integer_t>()) as mach_msg_type_number_t;
    kr(unsafe { task_info(task, flavor, &mut data as *mut T as task_info_t, &mut cnt) })?;
    Ok(data)
}

pub fn task_basic_info(task: task_t) -> Result<task_basic_info_data_t, kern_return_t> {
    task_info_as(task, TASK_BASIC_INFO)
}
pub fn task_events_info(task: task_t) -> Result<task_events_info_data_t, kern_return_t> {
    task_info_as(task, TASK_EVENTS_INFO)
}
pub fn task_thread_times_info(task: task_t)
    -> Result<task_thread_times_info_data_t, kern_return_t>
{
    task_info_as(task, TASK_THREAD_TIMES_INFO)
}

/// Hilos de la tarea.  Cada elemento es un derecho de envío del que el
/// llamante es responsable (liberar con mach_port_deallocate).
pub fn task_thread_list(task: task_t) -> Result<Vec<thread_t>, kern_return_t> {
    let (mut list, mut cnt) = (std::ptr::null_mut(), 0);
    kr(unsafe { task_threads(task, &mut list, &mut cnt) })?;
    Ok(unsafe { take_ool(list, cnt) })
}

pub fn task_suspend_checked(task: task_t) -> Result<(), kern_return_t> {
    kr(unsafe { task_suspend(task) })
}
pub fn task_resume_checked(task: task_t) -> Result<(), kern_return_t> {
    kr(unsafe { task_resume(task) })
}
