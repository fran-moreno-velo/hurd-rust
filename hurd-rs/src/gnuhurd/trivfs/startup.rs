//===========================================================================//
// crate::hurd::trivfs                                                       //
//---------------------------------------------------------------------------//
// From github - gnuhurd                                                     //
// /hurd/libtrivfs/trivfs.h                                                  //
//===========================================================================//

// Import types

use crate::debug;
use crate::gnuhurd::mig_user::file_set_translator;
use crate::gnuhurd::types::FS_TRANS_SET;
use crate::gnumach::port::mach_port_t;
use crate::gnumach::error::mach_error_t;
use crate::gnuhurd::ports::port_class_t;
use crate::gnuhurd::ports::port_bucket_t;
use crate::gnuhurd::trivfs::types::trivfs_control_t;
use crate::gnuhurd::trivfs::symbols::{support_read, support_write, support_exec};

use std::ffi::c_char;
use std::ffi::{c_int,c_void};

// Import constants

use crate::gnumach::port::MACH_PORT_NULL;
use crate::gnumach::error::ERR_NONE;
use crate::gnumach::message::MACH_MSG_TYPE_COPY_SEND;
use crate::gnumach::error::EPERM;
use crate::gnumach::error::EMIG_BAD_ID;

// Import functions

use crate::gnumach::task::mach_task_self;
use crate::gnumach::port::mach_port_deallocate;

use crate::gnuhurd::trivfs::control::trivfs_create_control;
use crate::gnuhurd::ports::ports_get_send_right;
use crate::gnuhurd::ports::ports_port_deref;
use crate::gnuhurd::fsys::fsys_startup;
use crate::gnuhurd::process::getproc;
use crate::gnuhurd::process::proc_mark_important;

use libc::sigaction;
use errno::errno ;

//---------------------------------------------------------------------------//
// Translated functions                                                      //
//---------------------------------------------------------------------------//

/// Detects misconfigured translators: they declare `trivfs_support_* = 1` but
/// do not register the matching hook. Early diagnostics without C's abort
/// (§9.7). It is not an error: the RPC will return EOPNOTSUPP, but a warning
/// is emitted.
fn check_support_flags() {
    let read = support_read();
    let write = support_write();
    let exec = support_exec();
    if read != 0 && !crate::gnuhurd::trivfs::io_handlers::io_read_registered() {
        eprintln!("[trivfs] warning: trivfs_support_read=1 but no io_read hook registered");
    }
    if write != 0 && !crate::gnuhurd::trivfs::io_handlers::io_write_registered() {
        eprintln!("[trivfs] warning: trivfs_support_write=1 but no io_write hook registered");
    }
    if exec != 0 && !crate::gnuhurd::trivfs::file::file_exec_registered() {
        eprintln!("[trivfs] warning: trivfs_support_exec=1 but no file_exec hook registered");
    }
}

/* Creates a control port for this filesystem and sends it to BOOTSTRAP with
   fsys_startup.  CONTROL_TYPE is the ports library type for the control
   port, and PROTID_TYPE is the type for ports representing opens of this
   node.  If CONTROL isn't NULL, the trivfs control port is return in it.  If
   any error occurs sending fsys_startup, it is returned, otherwise 0.
   FLAGS specifies how to open the underlying node (O_*).  */
pub fn trivfs_startup(
      bootstrap: mach_port_t,
      flags: c_int,
      control_class: *mut port_class_t,
      control_bucket: *mut port_bucket_t,
      protid_class: *mut port_class_t,
      protid_bucket: *mut port_bucket_t,
      control: *mut *mut trivfs_control_t
    ) -> mach_error_t
{

  debug!("[DEBUG] trivfs_startup: enter");

  crate::gnuhurd::trivfs::demuxer::install_concise_panic_hook();

  check_support_flags();

  let mut underlying: mach_port_t = MACH_PORT_NULL;
  let mut fsys: *mut trivfs_control_t = std::ptr::null_mut();
  
  let mut err = trivfs_create_control (MACH_PORT_NULL,
			   control_class, control_bucket,
			   protid_class, protid_bucket,
			   &raw mut fsys);

  debug!("[DEBUG] trivfs_create_control returned: {}", err);

  if err != ERR_NONE { return err };

  let right: mach_port_t = unsafe{ ports_get_send_right (fsys as *mut c_void) };

  debug!("[DEBUG] got send right: {}", right);

  err = unsafe{ fsys_startup(bootstrap, flags, right,
                             MACH_MSG_TYPE_COPY_SEND, &mut underlying) };

  debug!("[DEBUG] fsys_startup returned: {}", err);

  debug!("[DEBUG] right = {}, underlying = {}", right, underlying);

  unsafe{ mach_port_deallocate (mach_task_self (), right) };

  debug!("[DEBUG] after mach_port_deallocate");

  if err == ERR_NONE {
    let fsys = unsafe { &mut *fsys };
    fsys.underlying = underlying;
  };

  debug!("[DEBUG] after setting underlying");

  unsafe{ ports_port_deref (fsys as *mut c_void) };

  debug!("[DEBUG] after ports_port_deref");

  if err == ERR_NONE && !control.is_null() { unsafe { *control = fsys } };

  debug!("[DEBUG] after setting control pointer, err={}", err);

  if err == ERR_NONE
  {
      let proc: mach_port_t = unsafe{ getproc () };

      debug!("[DEBUG] getproc returned: {}", proc);

      if proc == MACH_PORT_NULL { return ERR_NONE };
      err = unsafe{ proc_mark_important (proc) };

      debug!("[DEBUG] proc_mark_important returned: {}", err);

      if err == EPERM || err == EMIG_BAD_ID { err = ERR_NONE };
      unsafe{ mach_port_deallocate (mach_task_self (), proc) };
   };

  debug!("[DEBUG] trivfs_startup returning: {}", err);

  err
}

#[allow(non_upper_case_globals)]
pub static mut goaway: mach_port_t = 0;

/* #14: handler_sigterm makes an RPC (fsys_goaway) from a signal handler, which
   is not async-signal-safe; moreover `goaway` is written once before
   sigaction (happens-before). It is C-faithful behavior (startup.c) and this
   debug startup function is dead code in the current translators. */

/* don't mark us as important and install a SIGTERM handler, so we can be
    * easily killed by Ctrl-C */
// Note: on Hurd the `struct sigaction` models the handler/sigaction union as
// `sa_sigaction: sighandler_t` (== size_t), without `sa_handler` (unlike
// Linux). The handler must have the C ABI (`extern "C"`), not Rust's ABI.
pub unsafe extern "C" fn handler_sigterm(_signum: ::std::os::raw::c_int)
{
    let ee: mach_error_t;
    ee = unsafe { crate::gnuhurd::fsys::fsys_goaway(goaway, 0) };

    if ee == crate::gnuhurd::types::ESUCCESS as i32
    {
        unsafe { mach_port_deallocate (mach_task_self (), goaway) };
    }
    else if ee != libc::EBUSY as i32
    {
        /* Not nice */
        //error(99, err, cr"fsys_goaway".as_ptr());
        unsafe { 
            crate::perror(cr"fsys_goaway".as_ptr());
            std::process::exit(99);
        };
    }
    /* else the translator is busy, please retry */
}


pub fn trivfs_startup_debug(
    file_name: *const c_char,
    control_class: *mut port_class_t,
    control_bucket: *mut port_bucket_t,
    protid_class: *mut port_class_t,
    protid_bucket: *mut port_bucket_t,
    control: *mut *mut trivfs_control_t,
  ) -> mach_error_t
{
    let underlying: mach_port_t;
    let right: mach_port_t;
    let mut fsys: *mut trivfs_control_t = std::ptr::null_mut();

    let mut err: mach_error_t =
    trivfs_create_control (MACH_PORT_NULL,
                control_class, control_bucket,
                protid_class, protid_bucket,
                &mut fsys);

    if err != 0{
        return err;
    }
    
    right = unsafe { ports_get_send_right (fsys as *mut c_void) };
    unsafe { goaway = ports_get_send_right (fsys as *mut c_void) };

    /* Start ourselves as transpator instead of replying to settrans */
    underlying = unsafe { crate::gnumach::port::file_name_lookup(file_name, 0, 0) };
    if underlying == MACH_PORT_NULL{
        err = errno().0;
    }
    
    else{
        err = unsafe { file_set_translator(underlying, 0,
                                           FS_TRANS_SET as i32,
                                           0, cr"".as_ptr(), 0,
                                           right, MACH_MSG_TYPE_COPY_SEND) };
    }
    unsafe { mach_port_deallocate (mach_task_self (), right) };


    if err == 0{
        (unsafe { *fsys }).underlying = underlying;
    }
    
    unsafe { ports_port_deref (fsys as *mut c_void) };

    /* Pass back what we got, unless the caller doesn't want it.  */
    if err == 0 && control != std::ptr::null_mut(){
        unsafe { *control = fsys };
    }
    
    let mut sa: sigaction = unsafe { std::mem::zeroed() };
    // sa_sigaction is sighandler_t (usize): the handler/sigaction union of
    // Hurd's sigaction. handler_sigterm is extern "C" fn(c_int) → C ABI.
    sa.sa_sigaction = handler_sigterm as *const () as usize;

    if unsafe { libc::sigaction(libc::SIGTERM, &sa as *const libc::sigaction, std::ptr::null_mut()) } < 0{
        err = errno().0;
    }

    return err;
}






