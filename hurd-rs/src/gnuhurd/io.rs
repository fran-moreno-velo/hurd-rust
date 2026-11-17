//===========================================================================//
// crate::gnuhurd::io                                                        //
//---------------------------------------------------------------------------//
// From github - gnuhurd                                                     //
//===========================================================================//

use std::ffi::{c_char, c_int, c_uint, c_ulong, c_longlong};
#[cfg(target_pointer_width = "64")]
use std::ffi::c_long;
use libc::{uid_t, dev_t, nlink_t, blksize_t, time_t};

use crate::gnumach::message::{mach_msg_type_name_t, mach_msg_type_number_t};
use crate::gnumach::port::mach_port_t;
use crate::gnumach::vm_types::{natural_t, vm_offset_t, vm_size_t};
use crate::gnuhurd::types::{ino64_t, timespec_t};
// Compatibilidad: antes estos nombres vivían en io.rs.
pub use crate::gnuhurd::idvec::idvec;
pub use crate::gnuhurd::iohelp::iouser;

use std::mem::size_of;
use crate::gnumach::error::mach_error_t;


//---------------------------------------------------------------------------//
// Types                                                                     //
//---------------------------------------------------------------------------//

pub type io_t         = mach_port_t;
pub type file_t       = mach_port_t;
pub type off64_t      = c_longlong;
pub type const_data_t = *const c_char;
pub type data_t       = *mut c_char;
pub type io_statbuf_t = io_statbuf;


#[cfg(target_pointer_width = "32")]
pub type loff_t = c_longlong;

#[cfg(target_pointer_width = "64")]
pub type loff_t = c_long;

pub type portarray_t = *mut mach_port_t;    // array[] of mach_port_send_t
pub type intarray_t  = *mut c_int;
pub type off_array_t = *mut loff_t;         // array[] of loff_t

//---------------------------------------------------------------------------//
// Structs                                                                   //
//---------------------------------------------------------------------------//


#[repr(C)]
#[derive(Copy, Clone)]
pub struct io_statbuf {
    pub st_fstype: u32,
    pub st_fsid: u64,
    pub st_ino: u64,
    pub st_gen: u32,
    pub st_rdev: dev_t,
    pub st_mode: u32,
    pub st_nlink: nlink_t,
    pub st_uid: u32,
    pub st_gid: u32,
    pub st_size: i64,
    pub st_atime: time_t,
    pub st_atimensec: c_ulong,
    pub st_mtime: time_t,
    pub st_mtimensec: c_ulong,
    pub st_ctime: time_t,
    pub st_ctimensec: c_ulong,
    pub st_blksize: blksize_t,
    pub st_blocks: i64,
    pub st_author: u32,
    pub st_flags: u32,
    pub st_spare: [i32; 8]
}
#[cfg(target_pointer_width = "32")]
const _: () = assert!(size_of::<io_statbuf>() == 128); //compilation guard
#[cfg(target_pointer_width = "64")]
const _: () = assert!(size_of::<io_statbuf>() == 176); //compilation guard

#[cfg(target_pointer_width = "32")]
const _: () = assert!(size_of::<fsys_statfsbuf_t>() == 88); // i686 wire layout
#[cfg(target_pointer_width = "64")]
const _: () = assert!(size_of::<fsys_statfsbuf_t>() == 96); // amd64, if apply

#[repr(C)]
pub struct fsys_statfsbuf_t {
    pub f_type: u32,
    pub f_bsize: u32,
    pub f_blocks: u64,
    pub f_bfree: u64,
    pub f_bavail: u64,
    pub f_files: u64,
    pub f_ffree: u64,
    pub f_fsid: u64,
    pub f_namelen: u32,
    pub f_favail: u64,
    pub f_frsize: u32,
    pub f_flag: u32,
    pub f_spare: [u32; 3],
}

//---------------------------------------------------------------------------//
// Constants                                                                 //
//---------------------------------------------------------------------------//

pub const SELECT_READ:  u32 = 1;
pub const SELECT_WRITE: u32 = 2;
pub const SELECT_URG:   u32 = 4;

pub const SEEK_SET: c_uint = 0;
pub const SEEK_CUR: c_uint = 1;
pub const SEEK_END: c_uint = 2;

//---------------------------------------------------------------------------//
// Stubs de cliente de io.defs (subsystem io 21000, libhurduser)             //
//---------------------------------------------------------------------------//
// Ver las convenciones de MIG en auth.rs.  "out data_t, dealloc" es
// (data_t *, Cnt *): entrada = buffer propio y capacidad; si la respuesta no
// cabe, *data apunta a memoria fuera de línea a liberar con vm_deallocate.

#[link(name = "hurduser")]
unsafe extern "C" {
    pub fn io_write(io_object: io_t,
                    data: const_data_t, data_cnt: mach_msg_type_number_t,
                    offset: loff_t, amount: *mut vm_size_t) -> mach_error_t;

    pub fn io_read(io_object: io_t,
                   data: *mut data_t, data_cnt: *mut mach_msg_type_number_t,
                   offset: loff_t, amount: vm_size_t) -> mach_error_t;

    pub fn io_seek(io_object: io_t, offset: loff_t, whence: c_int,
                   newp: *mut loff_t) -> mach_error_t;

    pub fn io_readable(io_object: io_t, amount: *mut vm_size_t) -> mach_error_t;

    pub fn io_set_all_openmodes(io_object: io_t, newbits: c_int) -> mach_error_t;
    pub fn io_get_openmodes(io_object: io_t, bits: *mut c_int) -> mach_error_t;
    pub fn io_set_some_openmodes(io_object: io_t, bits_to_set: c_int) -> mach_error_t;
    pub fn io_clear_some_openmodes(io_object: io_t, bits_to_clear: c_int) -> mach_error_t;

    pub fn io_async(io_object: io_t, notify_port: mach_port_t,
                    notify_port_poly: mach_msg_type_name_t,
                    async_id_port: *mut mach_port_t) -> mach_error_t;

    pub fn io_mod_owner(io_object: io_t, owner: libc::pid_t) -> mach_error_t;
    pub fn io_get_owner(io_object: io_t, owner: *mut libc::pid_t) -> mach_error_t;
    pub fn io_get_icky_async_id(io_object: io_t,
                                icky_async_id_port: *mut mach_port_t) -> mach_error_t;

    /// `reply` es el ureplyport (un derecho de recepción propio) y `timeout`
    /// el waittime en ms.  *select_type: entrada = SELECT_*, salida = listos.
    pub fn io_select(io_object: io_t, reply: mach_port_t, timeout: natural_t,
                     select_type: *mut c_int) -> mach_error_t;

    pub fn io_stat(stat_object: io_t, stat_info: *mut io_statbuf_t) -> mach_error_t;

    /// simpleroutine: seguir con auth_user_authenticate.
    pub fn io_reauthenticate(auth_object: io_t, rendezvous2: mach_port_t,
                             rendezvous2_poly: mach_msg_type_name_t) -> mach_error_t;

    pub fn io_restrict_auth(io_object: io_t, new_object: *mut mach_port_t,
                            uids: *const uid_t, uids_cnt: mach_msg_type_number_t,
                            gids: *const uid_t, gids_cnt: mach_msg_type_number_t)
        -> mach_error_t;

    pub fn io_duplicate(io_object: io_t, newport: *mut mach_port_t) -> mach_error_t;

    /// `server_name` debe apuntar a un buffer de STRING_T_SIZE bytes.
    pub fn io_server_version(vers_object: io_t, server_name: *mut c_char,
                             server_major_version: *mut c_int,
                             server_minor_version: *mut c_int,
                             server_edit_level: *mut c_int) -> mach_error_t;

    pub fn io_map(io_object: io_t, memobjrd: *mut mach_port_t,
                  memobjwt: *mut mach_port_t) -> mach_error_t;
    pub fn io_map_cntl(io_object: io_t, memobj: *mut mach_port_t) -> mach_error_t;
    pub fn io_get_conch(io_object: io_t) -> mach_error_t;
    pub fn io_release_conch(io_object: io_t) -> mach_error_t;
    pub fn io_eofnotify(io_object: io_t) -> mach_error_t;
    pub fn io_prenotify(io_object: io_t, write_start: vm_offset_t,
                        write_end: vm_offset_t) -> mach_error_t;
    pub fn io_postnotify(io_object: io_t, write_start: vm_offset_t,
                         write_end: vm_offset_t) -> mach_error_t;
    pub fn io_readnotify(io_object: io_t) -> mach_error_t;
    pub fn io_readsleep(io_object: io_t) -> mach_error_t;
    pub fn io_sigio(io_object: io_t) -> mach_error_t;

    pub fn io_pathconf(io_object: io_t, name: c_int, value: *mut c_int) -> mach_error_t;

    pub fn io_identity(io_object: io_t, idport: *mut mach_port_t,
                       fsidport: *mut mach_port_t, fileno: *mut ino64_t) -> mach_error_t;

    pub fn io_revoke(io_object: io_t) -> mach_error_t;

    pub fn io_select_timeout(io_object: io_t, reply: mach_port_t, timeout: timespec_t,
                             select_type: *mut c_int) -> mach_error_t;
}

/// Estado del objeto (io_stat).
pub fn io_stat_info(io: io_t) -> Result<io_statbuf_t, mach_error_t> {
    let mut st = std::mem::MaybeUninit::<io_statbuf_t>::zeroed();
    let err = unsafe { io_stat(io, st.as_mut_ptr()) };
    if err == 0 { Ok(unsafe { st.assume_init() }) } else { Err(err) }
}

