//===========================================================================//
// crate::gnumach::task                                                      //
//---------------------------------------------------------------------------//
// From gnumach-1.8+git20250304                                              //
// include/mach/task_special_ports.h                                         //
//===========================================================================//

use crate::gnumach::port::{mach_port_t, MACH_PORT_NULL};
use crate::gnumach::error::mach_error_t;


//---------------------------------------------------------------------------//
// Extern functions                                                          //
//---------------------------------------------------------------------------//

unsafe extern "C" {
  static mut __mach_task_self_: mach_port_t;

  pub fn task_get_special_port(task: mach_port_t, 
                               code: i32, 
                               port: *mut mach_port_t) -> mach_error_t;
  pub fn task_set_special_port(task: mach_port_t, 
                               code: i32, 
                               port: mach_port_t) -> mach_error_t;
}

//---------------------------------------------------------------------------//
// Public function                                                           //
//---------------------------------------------------------------------------//

#[inline]
pub fn mach_task_self() -> mach_port_t {
    unsafe { core::ptr::read_volatile(&raw const __mach_task_self_) }
}

//---------------------------------------------------------------------------//
// Internal constants                                                        //
//---------------------------------------------------------------------------//

const TASK_KERNEL_PORT: i32 = 1;
const TASK_EXCEPTION_PORT: i32 = 3;
const TASK_BOOTSTRAP_PORT: i32 = 4;

//---------------------------------------------------------------------------//
// Public get functions                                                      //
//---------------------------------------------------------------------------//

fn task_get_port(task: mach_port_t, which: i32) -> Result<mach_port_t, mach_error_t> {
    let mut port: mach_port_t = MACH_PORT_NULL;
    let err = unsafe { task_get_special_port(task, which, &mut port) };
    if err == 0 { Ok(port) } else { Err(err) }
}

pub fn task_get_kernel_port(task: mach_port_t) -> Result<mach_port_t, mach_error_t> {
    task_get_port(task, TASK_KERNEL_PORT)
}
pub fn task_get_exception_port(task: mach_port_t) -> Result<mach_port_t, mach_error_t> {
    task_get_port(task, TASK_EXCEPTION_PORT)
}
pub fn task_get_bootstrap_port(task: mach_port_t) -> Result<mach_port_t, mach_error_t> {
    task_get_port(task, TASK_BOOTSTRAP_PORT)
}

//---------------------------------------------------------------------------//
// Public set functions                                                      //
//---------------------------------------------------------------------------//

pub fn task_set_kernel_port(task: mach_port_t, 
                            port: mach_port_t) -> mach_error_t {
  unsafe { task_set_special_port(task, TASK_KERNEL_PORT, port) }
}

pub fn task_set_exception_port(task: mach_port_t, 
                               port: mach_port_t) -> mach_error_t {
  unsafe { task_set_special_port(task, TASK_EXCEPTION_PORT, port) }
}

pub fn task_set_bootstrap_port(task: mach_port_t, 
                               port: mach_port_t) -> mach_error_t {
  unsafe { task_set_special_port(task, TASK_BOOTSTRAP_PORT, port) }
}
