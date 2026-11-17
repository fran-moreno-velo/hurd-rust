//===========================================================================//
// crate::gnuhurd::fsys                                                      //
//---------------------------------------------------------------------------//
// From hurd/fsys.defs (subsystem fsys 22000) - stubs de cliente (libhurduser)//
//===========================================================================//
// Ver las convenciones de MIG en auth.rs.  "out data_t" es
// (data_t *, mach_msg_type_number_t *) con la misma regla de memoria fuera
// de línea; "out string_t" es un buffer de STRING_T_SIZE bytes.

use libc::uid_t;
use std::ffi::{c_char, c_int};
use crate::gnuhurd::io::{const_data_t, data_t, portarray_t};
use crate::gnuhurd::types::{auth_t, fsys_t, retry_type};
use crate::gnumach::kern_return::kern_return_t;
use crate::gnumach::message::{mach_msg_type_name_t, mach_msg_type_number_t};
use crate::gnumach::port::mach_port_t;

#[link(name = "hurduser")]
unsafe extern "C" {
    pub fn fsys_startup(bootstrap: mach_port_t,
                        openflags: c_int,
                        control_port: mach_port_t,
                        control_port_poly: mach_msg_type_name_t,
                        realnode: *mut mach_port_t) -> kern_return_t;

    pub fn fsys_goaway(fsys: fsys_t, flags: c_int) -> kern_return_t;

    /// `retry_name` debe apuntar a un buffer de STRING_T_SIZE bytes.
    pub fn fsys_getroot(fsys: fsys_t,
                        dotdot_node: mach_port_t,
                        dotdot_node_poly: mach_msg_type_name_t,
                        gen_uids: *const uid_t, gen_uids_cnt: mach_msg_type_number_t,
                        gen_gids: *const uid_t, gen_gids_cnt: mach_msg_type_number_t,
                        flags: c_int,
                        do_retry: *mut retry_type,
                        retry_name: *mut c_char,
                        file: *mut mach_port_t) -> kern_return_t;

    pub fn fsys_getfile(fsys: fsys_t,
                        gen_uids: *const uid_t, gen_uids_cnt: mach_msg_type_number_t,
                        gen_gids: *const uid_t, gen_gids_cnt: mach_msg_type_number_t,
                        filehandle: const_data_t, filehandle_cnt: mach_msg_type_number_t,
                        file: *mut mach_port_t) -> kern_return_t;

    pub fn fsys_syncfs(fsys: fsys_t, wait: c_int, do_children: c_int) -> kern_return_t;

    pub fn fsys_set_options(fsys: fsys_t,
                            options: const_data_t, options_cnt: mach_msg_type_number_t,
                            do_children: c_int) -> kern_return_t;

    pub fn fsys_getpriv(fsys: fsys_t,
                        host_priv: *mut mach_port_t,
                        device_master: *mut mach_port_t,
                        fstask: *mut mach_port_t) -> kern_return_t;

    pub fn fsys_init(fsys: fsys_t,
                     proc_server: mach_port_t,
                     proc_server_poly: mach_msg_type_name_t,
                     auth_handle: auth_t) -> kern_return_t;

    pub fn fsys_forward(server: mach_port_t,
                        requestor: mach_port_t,
                        requestor_poly: mach_msg_type_name_t,
                        argv: const_data_t, argv_cnt: mach_msg_type_number_t) -> kern_return_t;

    pub fn fsys_get_options(server: fsys_t,
                            options: *mut data_t,
                            options_cnt: *mut mach_msg_type_number_t) -> kern_return_t;

    pub fn fsys_get_children(server: fsys_t,
                             names: *mut data_t, names_cnt: *mut mach_msg_type_number_t,
                             controls: *mut portarray_t,
                             controls_cnt: *mut mach_msg_type_number_t) -> kern_return_t;

    /// `source` debe apuntar a un buffer de STRING_T_SIZE bytes.
    pub fn fsys_get_source(server: fsys_t, source: *mut c_char) -> kern_return_t;
}
