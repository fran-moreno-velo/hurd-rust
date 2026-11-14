//===========================================================================//
// crate::gnuhurd::ports                                                     //
//---------------------------------------------------------------------------//
// From github - gnuhurd                                                     //
// hurd/libports/ports.h                                                     //
// hurd/libports/port-deref-deferred.h                                       //
//===========================================================================//

use crate::gnumach::kern_return::kern_return_t;
use crate::gnumach::port::mach_port_t;
use crate::gnumach::port::mach_port_mscount_t;
use crate::gnumach::message::mach_msg_header_t;
use crate::gnumach::message::mach_msg_seqno_t;
use crate::gnumach::message::mach_msg_id_t;
use crate::gnumach::message::mach_msg_demux_t;
use crate::gnumach::mig::mig_routine_t;
use crate::gnumach::boolean;
use crate::gnumach::boolean::boolean_t;
use crate::gnumach::notify;
use crate::gnumach::error::mach_error_t;
use crate::gnumach::mach_types::thread_t;
use crate::gnuhurd::ihash::hurd_ihash;
use crate::gnuhurd::ihash::hurd_ihash_locp_t;
use crate::gnuhurd::types::refcounts_t;
use crate::gnuhurd::types::pthread_mutex_t;
use crate::gnuhurd::types::pthread_spinlock_t;
use std::ffi::{c_int, c_uint, c_void};

//---------------------------------------------------------------------------//
// Extern functions                                                          //
//---------------------------------------------------------------------------//

#[link(name="ports", kind="dylib")]
unsafe extern "C" {
  pub fn _ports_remove_notified_rpc(rpc: *mut rpc_info_t);

  pub fn ports_create_bucket() -> *mut port_bucket_t;

  pub fn ports_create_class(
    clean_routine: Option<unsafe extern "C" fn(*mut c_void) >,
    dropweak_routine: Option<unsafe extern "C" fn(*mut c_void) >,
  ) -> *mut port_class_t;

  pub fn ports_create_port(
        port_class: *mut port_class_t,
        bucket: *mut port_bucket_t,
        size: usize,
        result: *mut c_void
    ) -> mach_error_t;

  pub fn ports_create_port_noinstall(
        port_class: *mut port_class_t,
        bucket: *mut port_bucket_t,
        size: usize,
        result: *mut c_void
    ) -> mach_error_t;

  pub fn ports_import_port (
        port_class: *mut port_class_t,
        bucket: *mut port_bucket_t,
        port: mach_port_t,
        size: usize,
        result: *mut c_void
    ) -> mach_error_t;

  pub fn ports_reallocate_port(
        port: *mut c_void
    );

  pub fn ports_reallocate_from_external(
        port: *mut c_void, 
        receive: mach_port_t
    );

  pub fn ports_destroy_right(
        port: *mut c_void
    ) -> mach_error_t;

  pub fn ports_claim_right(
        port: *mut c_void
    ) -> mach_port_t;

  pub fn ports_transfer_right(
        topt: *mut c_void,
        frompt: *mut c_void,
    ) -> mach_error_t;

  pub fn ports_get_right(
        port: *mut c_void
    ) -> mach_port_t;

  pub fn ports_get_send_right(
        port: *mut c_void
    ) -> mach_port_t;

  pub fn ports_lookup_port(
        bucket: *mut port_bucket_t,
        port: mach_port_t,
        port_class: *mut port_class_t,
    ) -> *mut c_void;

  pub fn ports_lookup_payload(
        bucket: *mut port_bucket_t,
        payload: usize,
        port_class: *mut port_class_t,
    ) -> *mut c_void;

  pub fn ports_payload_get_name(
        payload: usize
    ) -> mach_port_t;

  pub fn ports_port_ref(
        port: *mut c_void
    );

  pub fn ports_port_ref_weak(
        port: *mut c_void
    );

  pub fn ports_port_deref(
        port: *mut c_void
    );

  pub fn ports_port_deref_weak(
        port: *mut c_void
    );

  pub fn ports_request_dead_name_notification (
        object: *mut c_void,
        name: mach_port_t,
        previous: *mut mach_port_t
    ) -> mach_error_t;

  pub fn ports_no_senders(
        port: *mut c_void, 
        mscount: mach_port_mscount_t
    );

  pub fn ports_dead_name(
       notify: *mut c_void, 
       dead_name: mach_port_t
    );

  pub fn ports_count_class(
        port_class: *mut port_class_t
    ) -> c_int;

  pub fn ports_count_bucket(
        bucket: *mut port_bucket_t
    ) -> c_int;

  pub fn ports_enable_class(
        port_class: *mut port_class_t
    );

  pub fn ports_enable_bucket(
        bucket: *mut port_bucket_t
    );

  pub fn ports_bucket_iterate(
        bucket: *mut port_bucket_t,
        fun: Option<unsafe extern "C" fn(port: *mut c_void) -> mach_error_t>
    ) -> mach_error_t;

  pub fn ports_class_iterate(
        port_class: *mut port_class_t,
        fun: Option<unsafe extern "C" fn(port: *mut c_void) -> mach_error_t>
    ) -> mach_error_t;

  pub fn _ports_bucket_class_iterate(
        ht: *mut hurd_ihash,
        port_class: *mut port_class_t,
        fun: Option<unsafe extern "C" fn(port: *mut c_void) -> mach_error_t>
    ) -> mach_error_t;

  pub fn ports_begin_rpc(
        port: *mut c_void,
        msg_id: mach_msg_id_t,
        info: *mut rpc_info_t,
    ) -> mach_error_t;

  pub fn ports_end_rpc(
        port: *mut c_void, 
        info: *mut rpc_info_t
    );

  pub fn ports_manage_port_operations_one_thread(
        bucket: *mut port_bucket_t,
        demuxer: ports_demuxer_t,
        timeout: c_int,
    );

  pub fn ports_manage_port_operations_multithread(
        bucket: *mut port_bucket_t,
        demuxer: ports_demuxer_t,
        thread_timeout: c_int,
        global_timeout: c_int,
        hook: Option<unsafe extern "C" fn()>
    );

  pub fn ports_inhibit_port_rpcs(
        port: *mut c_void
    ) -> mach_error_t;

  pub fn ports_inhibit_class_rpcs(
        port_class: *mut port_class_t
    ) -> mach_error_t;

  pub fn ports_inhibit_bucket_rpcs(
        bucket: *mut port_bucket_t
    ) -> mach_error_t;

  pub fn ports_inhibit_all_rpcs(
    ) -> mach_error_t;

  pub fn ports_resume_port_rpcs(
        port: *mut c_void
    );

  pub fn ports_resume_class_rpcs(
        port_class: *mut port_class_t
    );

  pub fn ports_resume_bucket_rpcs(
        bucket: *mut port_bucket_t
    );

  pub fn ports_resume_all_rpcs();

  pub fn ports_interrupt_rpcs(port: *mut c_void);

  pub fn ports_self_interrupted() -> c_int;

  pub fn _ports_record_interruption(rpc: *mut rpc_info_t);

  pub fn ports_interrupt_rpc_on_notification(
        object: *mut c_void,
        rpc: *mut rpc_info_t,
        port: mach_port_t,
        what: mach_msg_id_t
    ) -> mach_error_t;

  pub fn ports_interrupt_self_on_notification(
        object: *mut c_void,
        port: mach_port_t,
        what: mach_msg_id_t
    ) -> mach_error_t;

  pub fn ports_interrupt_notified_rpcs(
        object: *mut c_void,
        port: mach_port_t,
        what: mach_msg_id_t
    );

  pub fn ports_notify_server(
        arg1: *mut mach_msg_header_t,
        arg2: *mut mach_msg_header_t
    ) -> boolean_t;

  pub fn ports_do_mach_notify_dead_name(
        pi: *mut port_info_t,
        deadport: mach_port_t
    ) -> kern_return_t;

  pub fn ports_do_mach_notify_msg_accepted(
        pi: *mut port_info_t,
        name: mach_port_t,
    ) -> kern_return_t;

  pub fn ports_do_mach_notify_no_senders(
        pi: *mut port_info_t,
        count: mach_port_mscount_t
    ) -> kern_return_t;

  pub fn ports_do_mach_notify_port_deleted(
        pi: *mut port_info_t,
        name: mach_port_t
    ) -> kern_return_t;

  pub fn ports_do_mach_notify_port_destroyed(
        pi: *mut port_info_t,
        name: mach_port_t
    ) -> kern_return_t;

  pub fn ports_do_mach_notify_send_once(
        pi: *mut port_info_t
    ) -> kern_return_t;

  pub fn ports_interrupt_server(
        arg1: *mut mach_msg_header_t,
        arg2: *mut mach_msg_header_t,
    ) -> boolean_t;

  pub fn _ports_complete_deallocate(
        arg1: *mut port_info_t
    );

  pub fn _ports_create_port_internal(
        arg1: *mut port_class_t,
        arg2: *mut port_bucket_t,
        arg3: usize,
        arg4: *mut c_void,
        arg5: c_int,
    ) -> mach_error_t;

  pub fn _ports_threadpool_init (
          arg1: *mut ports_threadpool_t
         );

  pub fn _ports_thread_online(
          arg1: *mut ports_threadpool_t,
          arg2: *mut ports_thread_t
         );

  pub fn _ports_thread_quiescent (
          arg1: *mut ports_threadpool_t,
          arg2: *mut ports_thread_t
         );

  pub fn _ports_thread_offline (
          arg1: *mut ports_threadpool_t,
          arg2: *mut ports_thread_t
         );

  pub fn _ports_port_deref_deferred (
          arg1: *mut port_info_t
         );
}

//---------------------------------------------------------------------------//
// Public functions                                                          //
//---------------------------------------------------------------------------//

pub const PORTS_NOTIFY_MSGH_BASE: mach_msg_id_t = 64;
pub const PORTS_NOTIFY_MSGH_COUNT: mach_msg_id_t = 9;
pub const PORTS_INTERRUPT_MSGH_BASE: mach_msg_id_t = 33000;
pub const PORTS_INTERRUPT_MSGH_COUNT: mach_msg_id_t = 1;

pub unsafe fn ports_port_notify_right(port: *mut port_info_t) -> mach_port_t {
  unsafe {
    let bucket = (*port).bucket;
    let notify_port = (*bucket).notify_port;
    (*notify_port).port_right
  }
}

pub unsafe fn ports_port_is_notify(port: *mut port_info_t) -> boolean_t {
  unsafe {
     if port.is_null() {
       boolean::MACH_BOOLEAN_FALSE
     } else {
       let bucket = (*port).bucket;
       let notify_port = (*bucket).notify_port;
       if notify_port == port {
         boolean::MACH_BOOLEAN_TRUE
       } else {
         boolean::MACH_BOOLEAN_FALSE
       }
     }
  }
}

pub unsafe fn ports_interrupt_self_on_port_death(
      obj: *mut c_void, 
      port: mach_port_t
     ) -> mach_error_t {
  unsafe { 
    ports_interrupt_self_on_notification (obj, port, notify::MACH_NOTIFY_DEAD_NAME)
  }
}

unsafe extern "C" {
    /// Tabla generada por MIG (notify.defs, ids 64..=72). Las entradas sin
    /// rutina (64, 67, 68) son NULL, de ahí que mig_routine_t sea Option.
    pub static ports_notify_server_routines:
        [mig_routine_t; PORTS_NOTIFY_MSGH_COUNT as usize];

    /// Tabla generada por MIG (interrupt.defs, id 33000).
    pub static ports_interrupt_server_routines:
        [mig_routine_t; PORTS_INTERRUPT_MSGH_COUNT as usize];
}

/// Equivalente a la función inline que genera MIG en notify_S.h.
pub unsafe fn ports_notify_server_routine(inp: *const mach_msg_header_t) -> mig_routine_t {
    let idx = unsafe { (*inp).msgh_id }.wrapping_sub(PORTS_NOTIFY_MSGH_BASE);
    if !(0..PORTS_NOTIFY_MSGH_COUNT).contains(&idx) {
        return None;
    }
    unsafe { ports_notify_server_routines[idx as usize] }
}

/// Equivalente a la función inline que genera MIG en interrupt_S.h.
pub unsafe fn ports_interrupt_server_routine(inp: *const mach_msg_header_t) -> mig_routine_t {
    let idx = unsafe { (*inp).msgh_id }.wrapping_sub(PORTS_INTERRUPT_MSGH_BASE);
    if !(0..PORTS_INTERRUPT_MSGH_COUNT).contains(&idx) {
        return None;
    }
    unsafe { ports_interrupt_server_routines[idx as usize] }
}


//---------------------------------------------------------------------------//
// Type ports_demuxer_t                                                      //
//---------------------------------------------------------------------------//

pub type ports_demuxer_t = mach_msg_demux_t;

//---------------------------------------------------------------------------//
// Type ports_flag_t                                                         //
//---------------------------------------------------------------------------//

pub type ports_flag_t = c_int;

/* These are global values for common flags used in the various structures.
   Not all of these are meaningful in all flag fields.  */
pub const PORTS_INHIBITED: ports_flag_t    = 0x0100; /* block RPC's */
pub const PORTS_BLOCKED: ports_flag_t      = 0x0200; /* if INHIBITED, someone is blocked */
pub const PORTS_INHIBIT_WAIT: ports_flag_t = 0x0400; /* someone wants to start inhibit */
pub const PORTS_NO_ALLOC: ports_flag_t     = 0x0800; /* block allocation */
pub const PORTS_ALLOC_WAIT: ports_flag_t   = 0x1000; /* someone wants to allocate */

/* FLAGS in port_info are the following: */
pub const PORT_HAS_SENDRIGHTS: ports_flag_t = 0x0001; /* send rights extant */
pub const PORT_INHIBITED: ports_flag_t      = PORTS_INHIBITED;
pub const PORT_BLOCKED: ports_flag_t        = PORTS_BLOCKED;
pub const PORT_INHIBIT_WAIT: ports_flag_t   = PORTS_INHIBIT_WAIT;

/* FLAGS in port_bucket are the following: */
pub const PORT_BUCKET_INHIBITED: ports_flag_t    = PORTS_INHIBITED;
pub const PORT_BUCKET_BLOCKED: ports_flag_t      = PORTS_BLOCKED;
pub const PORT_BUCKET_INHIBIT_WAIT: ports_flag_t = PORTS_INHIBIT_WAIT;
pub const PORT_BUCKET_NO_ALLOC: ports_flag_t     = PORTS_NO_ALLOC;
pub const PORT_BUCKET_ALLOC_WAIT: ports_flag_t   = PORTS_ALLOC_WAIT;

/* FLAGS in port_class are the following: */
pub const PORT_CLASS_INHIBITED: ports_flag_t    = PORTS_INHIBITED;
pub const PORT_CLASS_BLOCKED: ports_flag_t      = PORTS_BLOCKED;
pub const PORT_CLASS_INHIBIT_WAIT: ports_flag_t = PORTS_INHIBIT_WAIT;
pub const PORT_CLASS_NO_ALLOC: ports_flag_t     = PORTS_NO_ALLOC;
pub const PORT_CLASS_ALLOC_WAIT: ports_flag_t   = PORTS_ALLOC_WAIT;

//---------------------------------------------------------------------------//
// Type port_info_t                                                          //
//---------------------------------------------------------------------------//

#[repr(C)]
#[derive(Copy, Clone)]
pub struct port_info_t {
  pub class: *mut port_class_t,
  pub refcounts: refcounts_t,
  pub mscount: mach_port_mscount_t,
  pub cancel_threshold: mach_msg_seqno_t,
  pub flags: ports_flag_t,
  pub port_right: mach_port_t,
  pub current_rpcs: *mut rpc_info_t,
  pub bucket: *mut port_bucket_t,
  pub hentry: hurd_ihash_locp_t,
  pub ports_htable_entry: hurd_ihash_locp_t,
}

//---------------------------------------------------------------------------//
// Type port_bucket_t                                                        //
//---------------------------------------------------------------------------//

#[repr(C)]
pub struct port_bucket_t {
  pub portset: mach_port_t,
  pub htable: hurd_ihash,
  pub rpcs: c_int,
  pub flags: ports_flag_t,
  pub count: c_int,
  pub threadpool: ports_threadpool_t,
  pub notify_port: *mut port_info_t
}

//---------------------------------------------------------------------------//
// Type port_class_t                                                         //
//---------------------------------------------------------------------------//

#[repr(C)]
#[derive(Copy, Clone)]
pub struct port_class_t {
  pub flags: ports_flag_t,
  pub rpcs: c_int,
  pub count: c_int,
  pub clean_routine: Option<unsafe extern "C" fn(arg1: *mut c_void)>,
  pub dropweak_routine: Option<unsafe extern "C" fn(arg1: *mut c_void)>,
  pub uninhibitable_rpcs: *mut ports_msg_id_range_t
}

//---------------------------------------------------------------------------//
// Type rpc_info_t                                                           //
//---------------------------------------------------------------------------//

#[repr(C)]
#[derive(Copy, Clone)]
pub struct rpc_info_t {
  pub thread: thread_t,
  pub next: *mut rpc_info_t,
  pub prev: *mut *mut rpc_info_t,
  pub notifies: *mut rpc_notify_t,
  pub interrupted_next: *mut rpc_info_t
}

//---------------------------------------------------------------------------//
// Type rpc_notify_t                                                         //
//---------------------------------------------------------------------------//

#[repr(C)]
#[derive(Copy, Clone)]
pub struct rpc_notify_t {
  pub rpc: *mut rpc_info_t,		/* Which rpc this is for. */
  pub notify: *mut ports_notify_t, 	/* Which port/request this refers too. */
  pub next: *mut rpc_notify_t,		/* Notify for this rpc. */
  pub pending: c_uint,			/* Number of requests this represents.  */
  pub next_req: *mut rpc_notify_t,	/* rpc for this notify.  */
  pub prev_req_p: *mut *mut rpc_notify_t /* who points to this rpc_notify. */
}

//---------------------------------------------------------------------------//
// Type ports_notify_t                                                       //
//---------------------------------------------------------------------------//

#[repr(C)]
pub struct ports_notify_t {
    pub port: mach_port_t,
    pub what: mach_msg_id_t,
    pub pending: c_uint,
    pub lock: pthread_mutex_t,
    pub reqs: *mut rpc_notify_t,
    pub next: *mut ports_notify_t,
    pub prevp: *mut *mut ports_notify_t,
}

//---------------------------------------------------------------------------//
// Type ports_msg_id_range_t                                                 //
//---------------------------------------------------------------------------//

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ports_msg_id_range_t {
  pub start: mach_msg_id_t,
  pub end: mach_msg_id_t,
  pub next: *mut ports_msg_id_range_t
}

//---------------------------------------------------------------------------//
// Type ports_threadpool_t                                                   //
//---------------------------------------------------------------------------//

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ports_threadpool_t {
  pub lock: pthread_spinlock_t,
  pub color: c_uint,
  pub old_threads: usize,
  pub old_objects: *mut port_info_t,
  pub young_threads: usize,
  pub young_objects: *mut port_info_t,
}
//---------------------------------------------------------------------------//
// Type ports_thread_t                                                       //
//---------------------------------------------------------------------------//

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ports_thread_t {
  pub color: c_uint,
}

