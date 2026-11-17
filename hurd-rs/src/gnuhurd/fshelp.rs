//===========================================================================//
// crate::gnuhurd::fshelp                                                    //
//---------------------------------------------------------------------------//
// From hurd libfshelp/fshelp.h  (instalada como <hurd/fshelp.h>)            //
//===========================================================================//
// Funciones de ayuda para servidores de ficheros (translators).  Tipos que
// dependen de cabeceras no traducidas se pasan como punteros opacos:
// struct flock64 y struct argp como *mut/*const c_void, struct rlock_list
// como un tipo opaco.

use libc::{gid_t, mode_t, uid_t};
use std::ffi::{c_char, c_int, c_uint, c_void};
use crate::gnuhurd::idvec::idvec;
use crate::gnuhurd::io::{file_t, io_statbuf_t, loff_t};
use crate::gnuhurd::iohelp::iouser;
use crate::gnuhurd::ports::{port_bucket_t, port_info_t};
use crate::gnuhurd::types::{auth_t, fsys_t, ino64_t, pthread_cond_t, pthread_mutex_t,
                            retry_type};
use crate::gnumach::error::mach_error_t;
use crate::gnumach::mach_types::task_t;
use crate::gnumach::message::{mach_msg_type_name_t, mach_msg_type_number_t};
use crate::gnumach::port::mach_port_t;
use crate::gnumach::time_value::mapped_time_value_t;

//---------------------------------------------------------------------------//
// Tipos                                                                     //
//---------------------------------------------------------------------------//

/// Callback que abre el nodo subyacente para un translator pasivo.
pub type fshelp_open_fn_t = Option<unsafe extern "C" fn(
    flags: c_int, node: *mut file_t, node_type: *mut mach_msg_type_name_t,
    task: task_t, cookie: *mut c_void) -> mach_error_t>;

#[repr(C)]
pub struct transbox {
    pub active: fsys_t,
    pub lock: *mut pthread_mutex_t,
    pub flags: c_int,
    pub wakeup: pthread_cond_t,
    pub cookie: *mut c_void,
}
pub const TRANSBOX_STARTING: c_int = 1;
pub const TRANSBOX_WANTED: c_int   = 2;

pub type fshelp_fetch_root_callback1_t = Option<unsafe extern "C" fn(
    cookie1: *mut c_void, cookie2: *mut c_void, uid: *mut uid_t, gid: *mut gid_t,
    argz: *mut *mut c_char, argz_len: *mut mach_msg_type_number_t) -> mach_error_t>;

pub type fshelp_fetch_root_callback2_t = Option<unsafe extern "C" fn(
    cookie1: *mut c_void, cookie2: *mut c_void, flags: c_int,
    underlying: *mut mach_port_t,
    underlying_type: *mut mach_msg_type_name_t) -> mach_error_t>;

/// Cookie para fshelp_short_circuited_callback1.
#[repr(C)]
pub struct fshelp_stat_cookie2 {
    pub statp: *mut io_statbuf_t,
    pub modep: *mut mode_t,
    pub next: *mut c_void,
}

#[repr(C)]
pub struct lock_box {
    pub type_: c_int,               // `type` en C
    pub wait: pthread_cond_t,
    pub waiting: c_int,
    pub shcount: c_int,
}

/// Lista interna de locks de libfshelp (opaca).
#[repr(C)]
pub struct rlock_list {
    _private: [u8; 0],
}

#[repr(C)]
pub struct rlock_box {
    pub locks: *mut rlock_list,
}

#[repr(C)]
pub struct rlock_peropen {
    pub locks: *mut *mut rlock_list,
}

// Timestamps para fshelp_touch.
pub const TOUCH_ATIME: c_uint = 0x1;
pub const TOUCH_MTIME: c_uint = 0x2;
pub const TOUCH_CTIME: c_uint = 0x4;

//---------------------------------------------------------------------------//
// Funciones                                                                 //
//---------------------------------------------------------------------------//

#[link(name = "fshelp")]
unsafe extern "C" {
    // --- Translators activos ---
    pub fn fshelp_set_active_translator(pi: *mut port_info_t, name: *const c_char,
                                        transbox: *const transbox) -> mach_error_t;
    pub fn fshelp_remove_active_translator(active: mach_port_t) -> mach_error_t;
    pub fn fshelp_get_active_translators(translators: *mut *mut c_char,
                                         translators_len: *mut usize,
                                         controls: *mut *mut mach_port_t,
                                         controls_count: *mut usize) -> mach_error_t;
    pub fn fshelp_map_active_translators(
        fun: Option<unsafe extern "C" fn(cookie: *mut c_void, name: *const c_char,
                                         control: mach_port_t) -> mach_error_t>,
        cookie: *mut c_void) -> mach_error_t;

    // --- Arranque de translators pasivos ---
    pub fn fshelp_start_translator_long(underlying_open_fn: fshelp_open_fn_t,
                                        cookie: *mut c_void, name: *mut c_char,
                                        argz: *mut c_char, argz_len: mach_msg_type_number_t,
                                        fds: *mut mach_port_t, fds_type: mach_msg_type_name_t,
                                        fds_len: mach_msg_type_number_t,
                                        ports: *mut mach_port_t, ports_type: mach_msg_type_name_t,
                                        ports_len: mach_msg_type_number_t,
                                        ints: *mut c_int, ints_len: mach_msg_type_number_t,
                                        owner_uid: uid_t, timeout: c_int,
                                        control: *mut fsys_t) -> mach_error_t;
    pub fn fshelp_start_translator(underlying_open_fn: fshelp_open_fn_t, cookie: *mut c_void,
                                   name: *mut c_char, argz: *mut c_char,
                                   argz_len: mach_msg_type_number_t, timeout: c_int,
                                   control: *mut fsys_t) -> mach_error_t;

    // --- Enlace con translators activos (transbox) ---
    pub fn fshelp_short_circuited_callback1(cookie1: *mut c_void, cookie2: *mut c_void,
                                            uid: *mut uid_t, gid: *mut gid_t,
                                            argz: *mut *mut c_char,
                                            argz_len: *mut mach_msg_type_number_t)
        -> mach_error_t;
    /// `retryname` debe apuntar a un buffer de STRING_T_SIZE bytes.  El lock
    /// del transbox debe estar tomado antes y lo estará al volver.
    pub fn fshelp_fetch_root(transbox: *mut transbox, cookie: *mut c_void, dotdot: file_t,
                             user: *mut iouser, flags: c_int,
                             callback1: fshelp_fetch_root_callback1_t,
                             callback2: fshelp_fetch_root_callback2_t,
                             retry: *mut retry_type, retryname: *mut c_char,
                             root: *mut mach_port_t) -> mach_error_t;
    pub fn fshelp_transbox_init(transbox: *mut transbox, lock: *mut pthread_mutex_t,
                                cookie: *mut c_void);
    pub fn fshelp_translated(box_: *mut transbox) -> c_int;
    pub fn fshelp_set_active(box_: *mut transbox, newactive: fsys_t, excl: c_int)
        -> mach_error_t;
    pub fn fshelp_fetch_control(box_: *mut transbox, control: *mut mach_port_t)
        -> mach_error_t;
    pub fn fshelp_drop_transbox(box_: *mut transbox);

    // --- flock ---
    pub fn fshelp_lock_init(box_: *mut lock_box);
    pub fn fshelp_acquire_lock(box_: *mut lock_box, user: *mut c_int,
                               mut_: *mut pthread_mutex_t, flags: c_int) -> mach_error_t;

    // --- Record locking (fcntl) ---
    pub fn fshelp_rlock_init(box_: *mut rlock_box) -> mach_error_t;
    pub fn fshelp_rlock_po_init(po: *mut rlock_peropen) -> mach_error_t;
    pub fn fshelp_rlock_drop_peropen(po: *mut rlock_peropen) -> mach_error_t;
    pub fn fshelp_rlock_po_fini(po: *mut rlock_peropen) -> mach_error_t;
    /// `lock` apunta a un struct flock64 de <fcntl.h> (VERIFICAR su diseño).
    pub fn fshelp_rlock_tweak(box_: *mut rlock_box, mutex: *mut pthread_mutex_t,
                              po: *mut rlock_peropen, open_mode: c_int, size: loff_t,
                              curpointer: loff_t, cmd: c_int, lock: *mut c_void,
                              rendezvous: mach_port_t) -> mach_error_t;
    pub fn fshelp_rlock_peropen_status(po: *mut rlock_peropen) -> c_int;
    pub fn fshelp_rlock_node_status(box_: *mut rlock_box) -> c_int;

    // --- Varios ---
    pub fn fshelp_get_identity(bucket: *mut port_bucket_t, fileno: ino64_t,
                               pt: *mut mach_port_t) -> mach_error_t;
    pub fn fshelp_delegate_translation(server_name: *const c_char, requestor: mach_port_t,
                                       argv: *mut *mut c_char) -> mach_error_t;
    pub fn fshelp_exec_reauth(suid: c_int, uid: uid_t, sgid: c_int, gid: gid_t, auth: auth_t,
                              get_file_ids: Option<unsafe extern "C" fn(
                                  uids: *mut idvec, gids: *mut idvec) -> mach_error_t>,
                              ports: *mut mach_port_t, num_ports: mach_msg_type_number_t,
                              fds: *mut mach_port_t, num_fds: mach_msg_type_number_t,
                              secure: *mut c_int) -> mach_error_t;
    /// `argp` apunta a un struct argp (no traducido aquí).
    pub fn fshelp_set_options(argp: *const c_void, flags: c_int, argz: *const c_char,
                              argz_len: usize, input: *mut c_void) -> mach_error_t;

    // --- Comprobación de permisos ---
    pub fn fshelp_isowner(st: *mut io_statbuf_t, user: *mut iouser) -> mach_error_t;
    pub fn fshelp_iscontroller(st: *mut io_statbuf_t, user: *mut iouser) -> mach_error_t;
    /// `op` es S_IREAD, S_IWRITE o S_IEXEC.
    pub fn fshelp_access(st: *mut io_statbuf_t, op: c_int, user: *mut iouser) -> mach_error_t;
    pub fn fshelp_checkdirmod(dir: *mut io_statbuf_t, st: *mut io_statbuf_t,
                              user: *mut iouser) -> mach_error_t;
    pub fn fshelp_touch(st: *mut io_statbuf_t, what: c_uint,
                        maptime: *const mapped_time_value_t);
}
