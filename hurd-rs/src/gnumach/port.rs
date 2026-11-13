//===========================================================================//
// crate::gnumach::port                                                      //
//---------------------------------------------------------------------------//
// From gnumach-1.8+git20250304                                              //
// include/mach/port.h                                                       //
// include/mach/mach_port.defs                                               //
//===========================================================================//

use crate::gnumach::boolean::boolean_t;
use crate::gnumach::error::mach_error_t;
use crate::gnumach::vm_types::{natural_t, integer_t};
#[cfg(target_pointer_width = "64")]
use crate::gnumach::vm_types::rpc_uintptr_t;
use std::ffi::{c_char, c_uint, c_int};

//---------------------------------------------------------------------------//
// Extern functions                                                          //
//---------------------------------------------------------------------------//

unsafe extern "C" {
  pub fn file_name_lookup(name: *const c_char,
                          flags: i32,
                          mode: i32) -> mach_port_t;

  pub fn mach_port_deallocate(task: mach_port_t, 
                              port: mach_port_t) -> mach_error_t;

  pub fn mach_port_allocate(task: mach_port_t, 
                            right: mach_port_right_t,
                            name: *mut mach_port_name_t) -> mach_error_t;

  pub fn mach_port_destroy(task: mach_port_t, 
                           port: mach_port_t) -> mach_error_t;

  pub fn mach_port_move_member(task: mach_port_t, 
                               member: mach_port_t, 
                               after: mach_port_t) -> mach_error_t;

  pub fn mach_port_request_notification(task: mach_port_t, 
                                        name: mach_port_t, 
                                        id: i32, 
                                        sync: u32,
                                        notify: mach_port_t, 
                                        notify_poly: u32,
                                        previous: *mut mach_port_t) -> mach_error_t;

  pub fn mach_port_mod_refs(task: mach_port_t,
                            name: mach_port_t,
                            right: mach_port_right_t,
                            delta: c_int) -> mach_error_t;
}

//---------------------------------------------------------------------------//
// Safe wrapper                                                          //
//---------------------------------------------------------------------------//

pub fn deallocate_port(task: mach_port_t, port: mach_port_t) -> mach_error_t {
      unsafe { mach_port_deallocate(task, port) }
}

//---------------------------------------------------------------------------//
// Type mach_port_t                                                          //
//---------------------------------------------------------------------------//

pub type mach_port_t = c_uint;
pub const MACH_PORT_NULL: mach_port_t = 0;
pub const MACH_PORT_DEAD: mach_port_t = !0;

pub fn mach_port_valid(port: mach_port_t) -> bool {
  port != MACH_PORT_NULL && port != MACH_PORT_DEAD
}

//---------------------------------------------------------------------------//
// Type mach_port_send_t                                                     //
//---------------------------------------------------------------------------//

/// Tipo MIG de std_types.defs: derecho de envío polimórfico (en C, un mach_port_t).
pub type mach_port_send_t = mach_port_t;

//---------------------------------------------------------------------------//
// Type mach_port_name_t                                                     //
//---------------------------------------------------------------------------//

pub type mach_port_name_t = c_uint;
pub const MACH_PORT_NAME_NULL: mach_port_name_t = 0;
pub const MACH_PORT_NAME_DEAD: mach_port_name_t = !0;

pub fn mach_port_name_valid(port: mach_port_name_t) -> bool {
  port != MACH_PORT_NAME_NULL && port != MACH_PORT_NAME_DEAD
}

//---------------------------------------------------------------------------//
// Type mach_port_name_inlined_t                                             //
//---------------------------------------------------------------------------//

#[cfg(target_pointer_width = "32")]
#[repr(C)]
pub union mach_port_name_inlined_t {
    pub name: mach_port_name_t,
    pub kernel_port: mach_port_t
}
#[cfg(target_pointer_width = "64")]
#[repr(C)]
pub union mach_port_name_inlined_t {
    pub name: mach_port_name_t,
    pub kernel_port_do_not_use: rpc_uintptr_t
}


//---------------------------------------------------------------------------//
// Type mach_port_right_t                                                    //
//---------------------------------------------------------------------------//

pub type mach_port_right_t = natural_t;

pub const MACH_PORT_RIGHT_SEND:      mach_port_right_t = 0;
pub const MACH_PORT_RIGHT_RECEIVE:   mach_port_right_t = 1;
pub const MACH_PORT_RIGHT_SEND_ONCE: mach_port_right_t = 2;
pub const MACH_PORT_RIGHT_PORT_SET:  mach_port_right_t = 3;
pub const MACH_PORT_RIGHT_DEAD_NAME: mach_port_right_t = 4;
pub const MACH_PORT_RIGHT_NUMBER:    mach_port_right_t = 5;

//---------------------------------------------------------------------------//
// Type mach_port_type_t                                                     //
//---------------------------------------------------------------------------//

pub type mach_port_type_t = natural_t;
pub const MACH_PORT_TYPE_NONE: mach_port_type_t      = 0;
pub const MACH_PORT_TYPE_SEND: mach_port_type_t      = 1 << 16;
pub const MACH_PORT_TYPE_RECEIVE: mach_port_type_t   = 1 << 17;
pub const MACH_PORT_TYPE_SEND_ONCE: mach_port_type_t = 1 << 18;
pub const MACH_PORT_TYPE_PORT_SET: mach_port_type_t  = 1 << 19;
pub const MACH_PORT_TYPE_DEAD_NAME: mach_port_type_t = 1 << 20;

/* Convenient combinations. */

pub const MACH_PORT_TYPE_SEND_RECEIVE: mach_port_type_t =
		MACH_PORT_TYPE_SEND | MACH_PORT_TYPE_RECEIVE;
pub const MACH_PORT_TYPE_SEND_RIGHTS: mach_port_type_t =
		MACH_PORT_TYPE_SEND | MACH_PORT_TYPE_SEND_ONCE;
pub const MACH_PORT_TYPE_PORT_RIGHTS: mach_port_type_t =
		MACH_PORT_TYPE_SEND_RIGHTS | MACH_PORT_TYPE_RECEIVE;
pub const MACH_PORT_TYPE_PORT_OR_DEAD: mach_port_type_t =
		MACH_PORT_TYPE_PORT_RIGHTS | MACH_PORT_TYPE_DEAD_NAME;
pub const MACH_PORT_TYPE_ALL_RIGHTS: mach_port_type_t =
		MACH_PORT_TYPE_PORT_OR_DEAD | MACH_PORT_TYPE_PORT_SET;

/* Dummy type bits that mach_port_type/mach_port_names can return. */

pub const MACH_PORT_TYPE_DNREQUEST: mach_port_type_t = 0x80000000u32;
pub const MACH_PORT_TYPE_MAREQUEST: mach_port_type_t = 0x40000000;
pub const MACH_PORT_TYPE_COMPAT: mach_port_type_t    = 0x20000000;

//---------------------------------------------------------------------------//
// Type mach_port_urefs_t                                                    //
//---------------------------------------------------------------------------//

pub type mach_port_urefs_t = natural_t;

//---------------------------------------------------------------------------//
// Type mach_port_delta_t                                                    //
//---------------------------------------------------------------------------//

pub type mach_port_delta_t = integer_t;

//---------------------------------------------------------------------------//
// Type mach_port_seqno_t                                                    //
//---------------------------------------------------------------------------//

pub type mach_port_seqno_t = natural_t;		/* sequence number */

//---------------------------------------------------------------------------//
// Type mach_port_mscount_t                                                  //
//---------------------------------------------------------------------------//

pub type mach_port_mscount_t = c_uint;	/* make-send count */

//---------------------------------------------------------------------------//
// Type mach_port_msgcount_t                                                 //
//---------------------------------------------------------------------------//

pub type mach_port_msgcount_t = c_uint;	/* number of msgs */

//---------------------------------------------------------------------------//
// Type mach_port_rights_t                                                   //
//---------------------------------------------------------------------------//

pub type mach_port_rights_t = c_uint;	/* number of rights */

//---------------------------------------------------------------------------//
// Type mach_port_status_t                                                   //
//---------------------------------------------------------------------------//

#[repr(C)]
pub struct mach_port_status_t {
  pub mps_pset: mach_port_name_t,         /* containing port set */
  pub mps_seqno: mach_port_seqno_t,       /* sequence number */
  pub mps_mscount: mach_port_mscount_t,   /* make-send count */
  pub mps_qlimit: mach_port_msgcount_t,   /* queue limit */
  pub mps_msgcount: mach_port_msgcount_t, /* number in the queue */
  pub mps_sorights: mach_port_rights_t,   /* how many send-once rights */
  pub mps_srights: boolean_t,             /* do send rights exist? */
  pub mps_pdrequest: boolean_t,           /* port-deleted requested? */
  pub mps_nsrequest: boolean_t            /* no-senders requested? */
}

pub const MACH_PORT_QLIMIT_DEFAULT: mach_port_msgcount_t = 5;
pub const MACH_PORT_QLIMIT_MAX: mach_port_msgcount_t = 16;
