//===========================================================================//
// crate::gnuhurd::fs                                                        //
//---------------------------------------------------------------------------//
// From hurd/fs.defs (subsystem fs 20000) - stubs de cliente (libhurduser)   //
//===========================================================================//
// Ver las convenciones de MIG en auth.rs.  Un "in" portarray_t lleva
// (puertos, Poly, Cnt); un "in" data_t lleva (datos, Cnt).

use libc::{gid_t, mode_t, uid_t};
use std::ffi::{c_char, c_int, c_void};
use crate::gnuhurd::io::{const_data_t, data_t, file_t, fsys_statfsbuf_t, intarray_t,
                         loff_t, off_array_t, portarray_t};
use crate::gnuhurd::types::{const_string_t, retry_type, timespec_t};
use crate::gnumach::kern_return::kern_return_t;
use crate::gnumach::mach_types::task_t;
use crate::gnumach::message::{mach_msg_type_name_t, mach_msg_type_number_t};
use crate::gnumach::port::{mach_port_name_t, mach_port_t};
use crate::gnumach::time_value::time_value_t;
use crate::gnumach::vm_types::vm_size_t;

#[link(name = "hurduser")]
unsafe extern "C" {
    /// Obsoleta: usar file_exec_paths.
    pub fn file_exec(exec_file: file_t, exec_task: task_t, flags: c_int,
                     argv: const_data_t, argv_cnt: mach_msg_type_number_t,
                     envp: const_data_t, envp_cnt: mach_msg_type_number_t,
                     fdarray: *mut mach_port_t, fdarray_poly: mach_msg_type_name_t,
                     fdarray_cnt: mach_msg_type_number_t,
                     portarray: *mut mach_port_t, portarray_poly: mach_msg_type_name_t,
                     portarray_cnt: mach_msg_type_number_t,
                     intarray: *const c_int, intarray_cnt: mach_msg_type_number_t,
                     deallocnames: *const mach_port_name_t, deallocnames_cnt: mach_msg_type_number_t,
                     destroynames: *const mach_port_name_t, destroynames_cnt: mach_msg_type_number_t)
        -> kern_return_t;

    pub fn file_chown(chown_file: file_t, new_owner: uid_t, new_group: gid_t) -> kern_return_t;
    pub fn file_chauthor(chauth_file: file_t, new_author: uid_t) -> kern_return_t;
    pub fn file_chmod(chmod_file: file_t, new_mode: mode_t) -> kern_return_t;
    pub fn file_chflags(chflags_file: file_t, new_flags: c_int) -> kern_return_t;

    /// microseconds == -1: usar la hora actual.  Preferir file_utimens.
    pub fn file_utimes(utimes_file: file_t, new_atime: time_value_t,
                       new_mtime: time_value_t) -> kern_return_t;

    pub fn file_set_size(trunc_file: file_t, new_size: loff_t) -> kern_return_t;
    pub fn file_lock(lock_file: file_t, flags: c_int) -> kern_return_t;
    pub fn file_lock_stat(lock_file: file_t, mystatus: *mut c_int,
                          otherstatus: *mut c_int) -> kern_return_t;
    /// *allowed: OR de O_READ, O_WRITE y O_EXEC.
    pub fn file_check_access(file: file_t, allowed: *mut c_int) -> kern_return_t;
    pub fn file_notice_changes(file: file_t, port: mach_port_t,
                               port_poly: mach_msg_type_name_t) -> kern_return_t;
    pub fn file_getcontrol(file: file_t, control: *mut mach_port_t) -> kern_return_t;
    pub fn file_statfs(file: file_t, info: *mut fsys_statfsbuf_t) -> kern_return_t;
    pub fn file_sync(file: file_t, wait: c_int, omit_metadata: c_int) -> kern_return_t;
    pub fn file_syncfs(file: file_t, wait: c_int, do_children: c_int) -> kern_return_t;

    pub fn file_get_storage_info(file: file_t,
                                 ports: *mut portarray_t, ports_cnt: *mut mach_msg_type_number_t,
                                 ints: *mut intarray_t, ints_cnt: *mut mach_msg_type_number_t,
                                 offsets: *mut off_array_t, offsets_cnt: *mut mach_msg_type_number_t,
                                 data: *mut data_t, data_cnt: *mut mach_msg_type_number_t)
        -> kern_return_t;

    pub fn file_getlinknode(file: file_t, linknode: *mut mach_port_t) -> kern_return_t;
    pub fn file_getfh(file: file_t, filehandle: *mut data_t,
                      filehandle_cnt: *mut mach_msg_type_number_t) -> kern_return_t;

    /// `retry_name` debe apuntar a un buffer de STRING_T_SIZE bytes.
    pub fn dir_lookup(start_dir: file_t, file_name: const_string_t, flags: c_int,
                      mode: mode_t, do_retry: *mut retry_type, retry_name: *mut c_char,
                      result: *mut mach_port_t) -> kern_return_t;

    /// Devuelve struct dirent consecutivas en *data (usar d_reclen para avanzar).
    pub fn dir_readdir(dir: file_t,
                       data: *mut data_t, data_cnt: *mut mach_msg_type_number_t,
                       entry: c_int, nentries: c_int, bufsiz: vm_size_t,
                       amount: *mut c_int) -> kern_return_t;

    pub fn dir_mkdir(directory: file_t, name: const_string_t, mode: mode_t) -> kern_return_t;
    pub fn dir_rmdir(directory: file_t, name: const_string_t) -> kern_return_t;
    pub fn dir_unlink(directory: file_t, name: const_string_t) -> kern_return_t;
    pub fn dir_link(dir: file_t, file: file_t, name: const_string_t,
                    excl: c_int) -> kern_return_t;
    pub fn dir_rename(olddirectory: file_t, oldname: const_string_t,
                      newdirectory: file_t, newname: const_string_t,
                      excl: c_int) -> kern_return_t;
    pub fn dir_mkfile(directory: file_t, flags: c_int, mode: mode_t,
                      newnode: *mut mach_port_t) -> kern_return_t;
    pub fn dir_notice_changes(directory: file_t, port: mach_port_t,
                              port_poly: mach_msg_type_name_t) -> kern_return_t;

    /// Flags FS_TRANS_*; `passive` es un argz ("/hurd/x\0arg1\0...").
    pub fn file_set_translator(file: file_t,
                               passive_flags: c_int, active_flags: c_int,
                               oldtrans_flags: c_int,
                               passive: const_data_t, passive_cnt: mach_msg_type_number_t,
                               active: mach_port_t,
                               active_poly: mach_msg_type_name_t) -> kern_return_t;

    pub fn file_get_translator(file: file_t, translator: *mut data_t,
                               translator_cnt: *mut mach_msg_type_number_t) -> kern_return_t;
    pub fn file_get_translator_cntl(file: file_t,
                                    translator_cntl: *mut mach_port_t) -> kern_return_t;
    pub fn file_get_fs_options(file: file_t, options: *mut data_t,
                               options_cnt: *mut mach_msg_type_number_t) -> kern_return_t;
    pub fn file_reparent(file: file_t, parent: mach_port_t,
                         new_file: *mut mach_port_t) -> kern_return_t;

    pub fn file_exec_paths(exec_file: file_t, exec_task: task_t, flags: c_int,
                           path: const_string_t, abspath: const_string_t,
                           argv: const_data_t, argv_cnt: mach_msg_type_number_t,
                           envp: const_data_t, envp_cnt: mach_msg_type_number_t,
                           fdarray: *mut mach_port_t, fdarray_poly: mach_msg_type_name_t,
                           fdarray_cnt: mach_msg_type_number_t,
                           portarray: *mut mach_port_t, portarray_poly: mach_msg_type_name_t,
                           portarray_cnt: mach_msg_type_number_t,
                           intarray: *const c_int, intarray_cnt: mach_msg_type_number_t,
                           deallocnames: *const mach_port_name_t,
                           deallocnames_cnt: mach_msg_type_number_t,
                           destroynames: *const mach_port_name_t,
                           destroynames_cnt: mach_msg_type_number_t) -> kern_return_t;

    /// tv_nsec == UTIME_NOW: hora actual; UTIME_OMIT: no cambiar.
    pub fn file_utimens(utimes_file: file_t, new_atime: timespec_t,
                        new_mtime: timespec_t) -> kern_return_t;

    /// `flock64` apunta a un struct flock64 de <fcntl.h> (VERIFICAR su diseño).
    pub fn file_record_lock(file: file_t, cmd: c_int, flock64: *mut c_void,
                            rendezvous: mach_port_t,
                            rendezvous_poly: mach_msg_type_name_t) -> kern_return_t;
}
