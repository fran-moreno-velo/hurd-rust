//===========================================================================//
// crate::gnumach::port                                                      //
//---------------------------------------------------------------------------//
// From gnumach-1.8+git20250304                                              //
// include/mach/port.h                                                       //
// include/mach/mach_port.defs                                               //
//===========================================================================//

use crate::gnumach::boolean::boolean_t;
use crate::gnumach::kern_return::kern_return_t;
use crate::gnumach::mach_types::{ipc_space_t, thread_t};
use crate::gnumach::message::{mach_msg_id_t, mach_msg_type_name_t, mach_msg_type_number_t};
use crate::gnumach::vm_types::{integer_t, natural_t, rpc_uintptr_t, vm_address_t};
use crate::gnumach::vm_user::vm_deallocate;
use std::ffi::c_uint;
use std::mem::size_of;

//---------------------------------------------------------------------------//
// Extern functions                                                          //
//---------------------------------------------------------------------------//
// Stubs de cliente de mach_port.defs (subsystem 3200), en libc de Hurd.
// Los arrays "^array[] of" llegan fuera de línea: liberarlos con vm_deallocate.

unsafe extern "C" {
  pub fn mach_port_names(task: ipc_space_t,
                         names: *mut mach_port_name_array_t,
                         names_cnt: *mut mach_msg_type_number_t,
                         types: *mut mach_port_type_array_t,
                         types_cnt: *mut mach_msg_type_number_t) -> kern_return_t;

  pub fn mach_port_type(task: ipc_space_t,
                        name: mach_port_name_t,
                        ptype: *mut mach_port_type_t) -> kern_return_t;

  pub fn mach_port_rename(task: ipc_space_t,
                          old_name: mach_port_name_t,
                          new_name: mach_port_name_t) -> kern_return_t;

  pub fn mach_port_allocate_name(task: ipc_space_t,
                                 right: mach_port_right_t,
                                 name: mach_port_name_t) -> kern_return_t;

  pub fn mach_port_allocate(task: ipc_space_t,
                            right: mach_port_right_t,
                            name: *mut mach_port_name_t) -> kern_return_t;

  pub fn mach_port_destroy(task: ipc_space_t,
                           name: mach_port_name_t) -> kern_return_t;

  pub fn mach_port_deallocate(task: ipc_space_t,
                              name: mach_port_name_t) -> kern_return_t;

  pub fn mach_port_get_refs(task: ipc_space_t,
                            name: mach_port_name_t,
                            right: mach_port_right_t,
                            refs: *mut mach_port_urefs_t) -> kern_return_t;

  pub fn mach_port_mod_refs(task: ipc_space_t,
                            name: mach_port_name_t,
                            right: mach_port_right_t,
                            delta: mach_port_delta_t) -> kern_return_t;

  pub fn mach_port_set_qlimit(task: ipc_space_t,
                              name: mach_port_name_t,
                              qlimit: mach_port_msgcount_t) -> kern_return_t;

  pub fn mach_port_set_mscount(task: ipc_space_t,
                               name: mach_port_name_t,
                               mscount: mach_port_mscount_t) -> kern_return_t;

  pub fn mach_port_get_set_status(task: ipc_space_t,
                                  name: mach_port_name_t,
                                  members: *mut mach_port_name_array_t,
                                  members_cnt: *mut mach_msg_type_number_t) -> kern_return_t;

  pub fn mach_port_move_member(task: ipc_space_t,
                               member: mach_port_name_t,
                               after: mach_port_name_t) -> kern_return_t;

  pub fn mach_port_request_notification(task: ipc_space_t,
                                        name: mach_port_name_t,
                                        id: mach_msg_id_t,
                                        sync: mach_port_mscount_t,
                                        notify: mach_port_t,
                                        notify_poly: mach_msg_type_name_t,
                                        previous: *mut mach_port_t) -> kern_return_t;

  pub fn mach_port_insert_right(task: ipc_space_t,
                                name: mach_port_name_t,
                                poly: mach_port_t,
                                poly_poly: mach_msg_type_name_t) -> kern_return_t;

  pub fn mach_port_extract_right(task: ipc_space_t,
                                 name: mach_port_name_t,
                                 msgt_name: mach_msg_type_name_t,
                                 poly: *mut mach_port_t,
                                 poly_poly: *mut mach_msg_type_name_t) -> kern_return_t;

  pub fn mach_port_get_receive_status(task: ipc_space_t,
                                      name: mach_port_name_t,
                                      status: *mut mach_port_status_t) -> kern_return_t;

  pub fn mach_port_set_seqno(task: ipc_space_t,
                             name: mach_port_name_t,
                             seqno: mach_port_seqno_t) -> kern_return_t;

  pub fn mach_port_set_protected_payload(task: ipc_space_t,
                                         name: mach_port_name_t,
                                         payload: rpc_uintptr_t) -> kern_return_t;

  pub fn mach_port_clear_protected_payload(task: ipc_space_t,
                                           name: mach_port_name_t) -> kern_return_t;

  /// Trap: crea un derecho de recepción nuevo (para respuestas).
  pub fn mach_reply_port() -> mach_port_t;

  /// Trap: devuelve una referencia NUEVA al puerto del hilo; liberarla.
  pub fn mach_thread_self() -> thread_t;
}

//---------------------------------------------------------------------------//
// Safe wrappers                                                             //
//---------------------------------------------------------------------------//

#[inline]
fn kr(err: kern_return_t) -> Result<(), kern_return_t> {
  if err == 0 { Ok(()) } else { Err(err) }
}

pub fn deallocate_port(task: ipc_space_t, port: mach_port_name_t) -> kern_return_t {
  unsafe { mach_port_deallocate(task, port) }
}

pub fn port_allocate(task: ipc_space_t, right: mach_port_right_t)
    -> Result<mach_port_name_t, kern_return_t> {
  let mut name = MACH_PORT_NULL;
  kr(unsafe { mach_port_allocate(task, right, &mut name) }).map(|_| name)
}

pub fn port_type(task: ipc_space_t, name: mach_port_name_t)
    -> Result<mach_port_type_t, kern_return_t> {
  let mut t: mach_port_type_t = 0;
  kr(unsafe { mach_port_type(task, name, &mut t) }).map(|_| t)
}

pub fn port_get_refs(task: ipc_space_t, name: mach_port_name_t, right: mach_port_right_t)
    -> Result<mach_port_urefs_t, kern_return_t> {
  let mut refs: mach_port_urefs_t = 0;
  kr(unsafe { mach_port_get_refs(task, name, right, &mut refs) }).map(|_| refs)
}

pub fn port_get_receive_status(task: ipc_space_t, name: mach_port_name_t)
    -> Result<mach_port_status_t, kern_return_t> {
  let mut st = mach_port_status_t::default();
  kr(unsafe { mach_port_get_receive_status(task, name, &mut st) }).map(|_| st)
}

/// Copia a un Vec un array fuera de línea devuelto por MIG y lo libera.
unsafe fn take_ool<T: Copy>(ptr: *mut T, cnt: mach_msg_type_number_t) -> Vec<T> {
  if ptr.is_null() || cnt == 0 { return Vec::new(); }
  let v = unsafe { std::slice::from_raw_parts(ptr, cnt as usize) }.to_vec();
  unsafe {
    vm_deallocate(crate::gnumach::task::mach_task_self(), ptr as vm_address_t,
                  cnt as usize * size_of::<T>());
  }
  v
}

/// Todos los nombres del espacio y su tipo (mach_port_names).
pub fn port_names(task: ipc_space_t)
    -> Result<Vec<(mach_port_name_t, mach_port_type_t)>, kern_return_t> {
  let (mut names, mut ncnt) = (std::ptr::null_mut(), 0);
  let (mut types, mut tcnt) = (std::ptr::null_mut(), 0);
  kr(unsafe { mach_port_names(task, &mut names, &mut ncnt, &mut types, &mut tcnt) })?;
  let names = unsafe { take_ool(names, ncnt) };
  let types = unsafe { take_ool(types, tcnt) };
  Ok(names.into_iter().zip(types).collect())
}

/// Miembros de un port set (mach_port_get_set_status).
pub fn port_set_members(task: ipc_space_t, set: mach_port_name_t)
    -> Result<Vec<mach_port_name_t>, kern_return_t> {
  let (mut members, mut cnt) = (std::ptr::null_mut(), 0);
  kr(unsafe { mach_port_get_set_status(task, set, &mut members, &mut cnt) })?;
  Ok(unsafe { take_ool(members, cnt) })
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
pub type mach_port_name_array_t = *mut mach_port_name_t;
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
pub type mach_port_type_array_t = *mut mach_port_type_t;
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
#[derive(Clone, Copy, Debug, Default)]
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
