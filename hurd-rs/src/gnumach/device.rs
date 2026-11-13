//===========================================================================//
// crate::gnumach::device                                                    //
//---------------------------------------------------------------------------//
// From gnumach                                                              //
// include/device/device_types.h                                             //
// include/device/device.defs  (subsystem device 2800)                       //
//===========================================================================//

use std::ffi::{c_char, c_int, c_short, c_uint};
use crate::gnumach::kern_return::kern_return_t;
use crate::gnumach::message::{mach_msg_type_name_t, mach_msg_type_number_t};
use crate::gnumach::port::mach_port_t;
use crate::gnumach::vm_types::{long_natural_t, vm_offset_t, vm_size_t};
use crate::gnumach::mach_types::memory_object_t;
use crate::gnumach::vm_prot::vm_prot_t;

//---------------------------------------------------------------------------//
// Types                                                                     //
//---------------------------------------------------------------------------//

pub type device_t = mach_port_t;

pub type dev_name_t = [c_char; 128];            // must match device_types.defs
pub type const_dev_name_t = *const c_char;

pub type dev_mode_t = c_uint;
pub type dev_flavor_t = c_uint;

pub type io_buf_ptr_t = *mut c_char;
pub type const_io_buf_ptr_t = *const c_char;

pub const IO_INBAND_MAX: usize = 128;           // must match device_types.defs
pub type io_buf_ptr_inband_t = [c_char; IO_INBAND_MAX];
pub type const_io_buf_ptr_inband_t = *const c_char;

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct io_buf_vec_t {
    pub data: vm_offset_t,
    pub count: vm_size_t,
}

pub type recnum_t = long_natural_t;             // 4 bytes en i386, 8 en LP64
pub type rpc_recnum_t = recnum_t;               // en espacio de usuario

pub type dev_status_t = *mut c_int;             // array variable de int
pub const DEV_STATUS_MAX: usize = 1024;
pub type dev_status_data_t = [c_int; DEV_STATUS_MAX];

pub type filter_t = c_short;
pub type filter_array_t = *mut filter_t;        // array[*:128] of filter_t

pub type io_return_t = c_int;

//---------------------------------------------------------------------------//
// Constants                                                                 //
//---------------------------------------------------------------------------//

pub const D_READ: dev_mode_t    = 0x1;          // read
pub const D_WRITE: dev_mode_t   = 0x2;          // write
pub const D_NODELAY: dev_mode_t = 0x4;          // no delay on open
pub const D_NOWAIT: dev_mode_t  = 0x8;          // do not wait if data not available

pub const DEV_GET_SIZE: dev_flavor_t = 0;
pub const DEV_GET_SIZE_DEVICE_SIZE: usize = 0;  // 0 if unknown
pub const DEV_GET_SIZE_RECORD_SIZE: usize = 1;  // 1 if sequential
pub const DEV_GET_SIZE_COUNT: mach_msg_type_number_t = 2;

pub const DEV_GET_RECORDS: dev_flavor_t = 1;
pub const DEV_GET_RECORDS_DEVICE_RECORDS: usize = 0;
pub const DEV_GET_RECORDS_RECORD_SIZE: usize = 1;
pub const DEV_GET_RECORDS_COUNT: mach_msg_type_number_t = 2;

pub const D_IO_QUEUED: io_return_t         = -1;   // IO queued - do not return result
pub const D_SUCCESS: io_return_t           = 0;
pub const D_IO_ERROR: io_return_t          = 2500; // hardware IO error
pub const D_WOULD_BLOCK: io_return_t       = 2501; // would block, but D_NOWAIT set
pub const D_NO_SUCH_DEVICE: io_return_t    = 2502; // no such device
pub const D_ALREADY_OPEN: io_return_t      = 2503; // exclusive-use device already open
pub const D_DEVICE_DOWN: io_return_t       = 2504; // device has been shut down
pub const D_INVALID_OPERATION: io_return_t = 2505; // bad operation for device
pub const D_INVALID_RECNUM: io_return_t    = 2506; // invalid record (block) number
pub const D_INVALID_SIZE: io_return_t      = 2507; // invalid IO size
pub const D_NO_MEMORY: io_return_t         = 2508; // memory allocation failure
pub const D_READ_ONLY: io_return_t         = 2509; // device cannot be written to

//---------------------------------------------------------------------------//
// MIG client stubs (device.defs)                                            //
//---------------------------------------------------------------------------//
// El reply_port de device.defs es "sreplyport": no aparece en el stub de
// cliente.  Los mach_port_send_t son polimórficos: llevan su argumento Poly.

unsafe extern "C" {
    pub fn device_open(master_port: mach_port_t, mode: dev_mode_t,
                       name: const_dev_name_t, device: *mut device_t) -> kern_return_t;

    pub fn device_close(device: device_t) -> kern_return_t;

    pub fn device_write(device: device_t, mode: dev_mode_t, recnum: recnum_t,
                        data: io_buf_ptr_t, data_cnt: mach_msg_type_number_t,
                        bytes_written: *mut c_int) -> kern_return_t;

    pub fn device_write_inband(device: device_t, mode: dev_mode_t, recnum: recnum_t,
                               data: const_io_buf_ptr_inband_t,
                               data_cnt: mach_msg_type_number_t,
                               bytes_written: *mut c_int) -> kern_return_t;

    /// Si devuelve éxito, *data apunta a memoria fuera de línea reservada en
    /// nuestro espacio: liberarla con vm_deallocate(mach_task_self(), *data, *data_cnt).
    pub fn device_read(device: device_t, mode: dev_mode_t, recnum: recnum_t,
                       bytes_wanted: c_int, data: *mut io_buf_ptr_t,
                       data_cnt: *mut mach_msg_type_number_t) -> kern_return_t;

    /// `data` debe apuntar a un buffer de al menos IO_INBAND_MAX bytes.
    pub fn device_read_inband(device: device_t, mode: dev_mode_t, recnum: recnum_t,
                              bytes_wanted: c_int, data: *mut c_char,
                              data_cnt: *mut mach_msg_type_number_t) -> kern_return_t;

    pub fn device_map(device: device_t, prot: vm_prot_t, offset: vm_offset_t,
                      size: vm_size_t, pager: *mut memory_object_t,
                      unmap: c_int) -> kern_return_t;

    pub fn device_set_status(device: device_t, flavor: dev_flavor_t,
                             status: dev_status_t,
                             status_cnt: mach_msg_type_number_t) -> kern_return_t;

    /// *status_cnt: entrada = capacidad del buffer (en int), salida = elementos devueltos.
    pub fn device_get_status(device: device_t, flavor: dev_flavor_t,
                             status: dev_status_t,
                             status_cnt: *mut mach_msg_type_number_t) -> kern_return_t;

    pub fn device_set_filter(device: device_t,
                             receive_port: mach_port_t, receive_port_poly: mach_msg_type_name_t,
                             priority: c_int, filter: filter_array_t,
                             filter_cnt: mach_msg_type_number_t) -> kern_return_t;

    pub fn device_intr_register(device: device_t, id: c_int, flags: c_int,
                                receive_port: mach_port_t,
                                receive_port_poly: mach_msg_type_name_t) -> kern_return_t;

    pub fn device_intr_ack(device: device_t, receive_port: mach_port_t,
                           receive_port_poly: mach_msg_type_name_t) -> kern_return_t;
}
