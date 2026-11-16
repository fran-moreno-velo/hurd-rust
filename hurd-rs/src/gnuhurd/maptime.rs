//===========================================================================//
// crate::gnuhurd::maptime                                                   //
//---------------------------------------------------------------------------//
// Equivalente a maptime_map de libshouldbeinlibc (maptime.c / maptime.h)    //
//===========================================================================//
// Mapea en memoria la página de tiempo que el núcleo actualiza continuamente,
// para leer la hora sin ninguna llamada al núcleo.  Dos orígenes, como en C:
//   - Dispositivo de Mach "time": necesita privilegios (get_privileged_ports).
//   - Fichero /dev/time (translator): basta con poder abrirlo; usa io_map.

use std::ffi::{CString, c_char};
use std::mem::size_of;

use crate::gnuhurd::fcntl::O_READ;
use crate::gnuhurd::io::io_map;
use crate::gnumach::device::{D_READ, device_map, device_open, device_t};
use crate::gnumach::error::{EINVAL, mach_error_t};
use crate::gnumach::host::get_privileged_ports;
use crate::gnumach::mach_types::memory_object_t;
use crate::gnuhurd::hurd::file_name_lookup;
use crate::gnumach::port::{MACH_PORT_NULL, mach_port_deallocate, mach_port_t};
use crate::gnumach::task::mach_task_self;
use crate::gnumach::time_value::{mapped_time_read, mapped_time_value_t, mapped_uptime_read, time_value64_t};
use crate::gnumach::vm_inherit::VM_INHERIT_NONE;
use crate::gnumach::vm_param::round_page;
use crate::gnumach::vm_prot::VM_PROT_READ;
use crate::gnumach::vm_types::{vm_address_t, vm_size_t};
use crate::gnumach::vm_user::{vm_deallocate, vm_map};


/// De dónde se obtiene la página de tiempo.
#[derive(Clone, Copy, Debug)]
pub enum TimeSource<'a> {
    /// Dispositivo de Mach (por defecto "time"). Solo para procesos privilegiados.
    MachDevice(Option<&'a str>),
    /// Fichero servido por un translator (por defecto "/dev/time").
    File(Option<&'a str>),
}

/// Página de tiempo mapeada en solo lectura. Se desmapea al destruirse.
pub struct MappedTime {
    page: *const mapped_time_value_t,
    size: vm_size_t,
}

// La página es de solo lectura y se lee con lecturas volátiles: se puede
// compartir entre hilos.
unsafe impl Send for MappedTime {}
unsafe impl Sync for MappedTime {}

impl MappedTime {
    /// Equivalente a maptime_map(use_mach_dev, dev_name, &mtime).
    pub fn map(source: TimeSource<'_>) -> Result<MappedTime, mach_error_t> {
        let task = mach_task_self();
        let memobj = match source {
            TimeSource::MachDevice(name) => memobj_from_device(name.unwrap_or("time"))?,
            TimeSource::File(name) => memobj_from_file(name.unwrap_or("/dev/time"))?,
        };

        let size = round_page(size_of::<mapped_time_value_t>());
        let mut addr: vm_address_t = 0;
        let err = unsafe {
            vm_map(task, &mut addr, size_of::<mapped_time_value_t>(), 0, 1, memobj,
                   0, 0, VM_PROT_READ, VM_PROT_READ, VM_INHERIT_NONE)
        };
        unsafe { mach_port_deallocate(task, memobj); }
        if err != 0 {
            return Err(err);
        }
        Ok(MappedTime { page: addr as *const mapped_time_value_t, size })
    }

    /// Hora actual (equivalente a maptime_read).
    pub fn now(&self) -> time_value64_t {
        unsafe { mapped_time_read(self.page) }
    }

    /// Tiempo desde el arranque del núcleo.
    pub fn uptime(&self) -> time_value64_t {
        unsafe { mapped_uptime_read(self.page) }
    }

    /// Puntero a la página, para código que necesite la estructura completa.
    pub fn as_ptr(&self) -> *const mapped_time_value_t {
        self.page
    }
}

impl Drop for MappedTime {
    fn drop(&mut self) {
        unsafe { vm_deallocate(mach_task_self(), self.page as vm_address_t, self.size); }
    }
}

fn memobj_from_device(name: &str) -> Result<memory_object_t, mach_error_t> {
    let task = mach_task_self();
    let cname = CString::new(name).map_err(|_| EINVAL)?;

    let mut master: mach_port_t = MACH_PORT_NULL;
    let err = unsafe { get_privileged_ports(std::ptr::null_mut(), &mut master) };
    if err != 0 {
        return Err(err);
    }

    let mut device: device_t = MACH_PORT_NULL;
    let err = unsafe { device_open(master, D_READ, cname.as_ptr(), &mut device) };
    unsafe { mach_port_deallocate(task, master); }
    if err != 0 {
        return Err(err);
    }

    let mut memobj: memory_object_t = MACH_PORT_NULL;
    let err = unsafe {
        device_map(device, VM_PROT_READ, 0, size_of::<mapped_time_value_t>(), &mut memobj, 0)
    };
    unsafe { mach_port_deallocate(task, device); }
    if err != 0 {
        return Err(err);
    }
    Ok(memobj)
}

fn memobj_from_file(name: &str) -> Result<memory_object_t, mach_error_t> {
    let task = mach_task_self();
    let cname = CString::new(name).map_err(|_| EINVAL)?;

    let node = unsafe { file_name_lookup(cname.as_ptr() as *const c_char, O_READ, 0) };
    if node == MACH_PORT_NULL {
        return Err(std::io::Error::last_os_error().raw_os_error().unwrap_or(0) as mach_error_t);
    }

    let mut rd: mach_port_t = MACH_PORT_NULL;
    let mut wr: mach_port_t = MACH_PORT_NULL;
    let err = unsafe { io_map(node, &mut rd, &mut wr) };
    unsafe { mach_port_deallocate(task, node); }
    if err != 0 {
        return Err(err);
    }
    if wr != MACH_PORT_NULL {
        unsafe { mach_port_deallocate(task, wr); }
    }
    if rd == MACH_PORT_NULL {
        return Err(EINVAL);
    }
    Ok(rd)
}
