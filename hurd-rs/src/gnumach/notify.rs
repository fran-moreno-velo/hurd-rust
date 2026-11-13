//===========================================================================//
// crate::gnumach::notify                                                    //
//---------------------------------------------------------------------------//
// From gnumach-1.8+git20250304                                              //
// include/mach/notify.h                                                     //
//===========================================================================//

use crate::gnumach::port::{mach_port_t, mach_port_name_t};
use crate::gnumach::message::{mach_msg_header_t, mach_msg_type_t, mach_msg_id_t };
use std::ffi::c_uint;

//---------------------------------------------------------------------------//
// Public constants                                                          //
//---------------------------------------------------------------------------//

pub const MACH_NOTIFY_FIRST:          mach_msg_id_t = 0o100;

pub const MACH_NOTIFY_PORT_DELETED:   mach_msg_id_t = MACH_NOTIFY_FIRST + 0o01;
pub const MACH_NOTIFY_MSG_ACCEPTED:   mach_msg_id_t = MACH_NOTIFY_FIRST + 0o02;
pub const MACH_NOTIFY_PORT_DESTROYED: mach_msg_id_t = MACH_NOTIFY_FIRST + 0o05;
pub const MACH_NOTIFY_NO_SENDERS:     mach_msg_id_t = MACH_NOTIFY_FIRST + 0o06;
pub const MACH_NOTIFY_SEND_ONCE:      mach_msg_id_t = MACH_NOTIFY_FIRST + 0o07;
pub const MACH_NOTIFY_DEAD_NAME:      mach_msg_id_t = MACH_NOTIFY_FIRST + 0o10;
pub const MACH_NOTIFY_LAST:           mach_msg_id_t = MACH_NOTIFY_FIRST + 0o15;

//---------------------------------------------------------------------------//
// Public types                                                              //
//---------------------------------------------------------------------------//

#[repr(C)]
pub struct  mach_port_deleted_notification_t {
  pub not_header: mach_msg_header_t,
  pub not_type: mach_msg_type_t,        /* MACH_MSG_TYPE_PORT_NAME */
  pub not_port: mach_port_name_t
}

#[repr(C)]
pub struct mach_msg_accepted_notification_t {
  pub not_header: mach_msg_header_t,
  pub not_type: mach_msg_type_t,        /* MACH_MSG_TYPE_PORT_NAME */
  pub not_port: mach_port_name_t
}

#[repr(C)]
pub struct mach_port_destroyed_notification_t{
  pub not_header: mach_msg_header_t,
  pub not_type: mach_msg_type_t,        /* MACH_MSG_TYPE_PORT_RECEIVE */
  pub not_port: mach_port_t
}

#[repr(C)]
pub struct  mach_no_senders_notification_t {
  pub not_header: mach_msg_header_t,
  pub not_type: mach_msg_type_t,        /* MACH_MSG_TYPE_INTEGER_32 */
  pub not_count:  c_uint
}

#[repr(C)]
pub struct mach_send_once_notification_t {
  pub not_header: mach_msg_header_t
}

#[repr(C)]
pub struct mach_dead_name_notification_t {
  pub not_header: mach_msg_header_t, 
  pub not_type: mach_msg_type_t,	/* MACH_MSG_TYPE_PORT_NAME */
  pub not_port: mach_port_name_t
}
