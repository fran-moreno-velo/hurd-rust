//===========================================================================//
// crate::gnuhurd::auth                                                      //
//---------------------------------------------------------------------------//
// From hurd/auth.defs (subsystem auth 25000) - stubs de cliente (libhurduser)//
//===========================================================================//
// Convenciones de MIG en el lado cliente:
//  - Un "in" mach_port_send_t / mach_port_poly_t lleva detrás su *Poly.
//  - Un "out" idarray_t es (uid_t **, mach_msg_type_number_t *): entrada =
//    buffer propio y su capacidad; si la respuesta no cabe, el puntero pasa a
//    apuntar a memoria fuera de línea que hay que liberar con vm_deallocate.
//  - Los "sreplyport" solo existen en el lado servidor: no aparecen aquí.

use libc::uid_t;
use crate::gnuhurd::types::auth_t;
use crate::gnumach::kern_return::kern_return_t;
use crate::gnumach::message::{mach_msg_type_name_t, mach_msg_type_number_t};
use crate::gnumach::port::mach_port_t;

#[link(name = "hurduser")]
unsafe extern "C" {
    pub fn auth_getids(handle: auth_t,
                       euids: *mut *mut uid_t, euids_cnt: *mut mach_msg_type_number_t,
                       auids: *mut *mut uid_t, auids_cnt: *mut mach_msg_type_number_t,
                       egids: *mut *mut uid_t, egids_cnt: *mut mach_msg_type_number_t,
                       agids: *mut *mut uid_t, agids_cnt: *mut mach_msg_type_number_t)
        -> kern_return_t;

    pub fn auth_makeauth(handle: auth_t,
                         other_handles: *mut mach_port_t,
                         other_handles_poly: mach_msg_type_name_t,
                         other_handles_cnt: mach_msg_type_number_t,
                         euids: *const uid_t, euids_cnt: mach_msg_type_number_t,
                         auids: *const uid_t, auids_cnt: mach_msg_type_number_t,
                         egids: *const uid_t, egids_cnt: mach_msg_type_number_t,
                         agids: *const uid_t, agids_cnt: mach_msg_type_number_t,
                         newhandle: *mut mach_port_t) -> kern_return_t;

    pub fn auth_user_authenticate(handle: auth_t,
                                  rendezvous: mach_port_t,
                                  rendezvous_poly: mach_msg_type_name_t,
                                  newport: *mut mach_port_t) -> kern_return_t;

    pub fn auth_server_authenticate(handle: auth_t,
                                    rendezvous: mach_port_t,
                                    rendezvous_poly: mach_msg_type_name_t,
                                    newport: mach_port_t,
                                    newport_poly: mach_msg_type_name_t,
                                    euids: *mut *mut uid_t, euids_cnt: *mut mach_msg_type_number_t,
                                    auids: *mut *mut uid_t, auids_cnt: *mut mach_msg_type_number_t,
                                    egids: *mut *mut uid_t, egids_cnt: *mut mach_msg_type_number_t,
                                    agids: *mut *mut uid_t, agids_cnt: *mut mach_msg_type_number_t)
        -> kern_return_t;
}
