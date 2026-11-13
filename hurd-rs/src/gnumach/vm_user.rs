//===========================================================================//
// crate::gnumach::vm_user                                                   //
//---------------------------------------------------------------------------//
// From gnumach-1.8+git20250304                                              //
// /include/mach/mach.defs  (rutinas vm_*)                                   //
//===========================================================================//
// Stubs de cliente generados por MIG (en libc de Hurd).
// pointer_t es "^array[] of MACH_MSG_TYPE_BYTE, ctype: vm_offset_t": en C
// se pasa como vm_offset_t + mach_msg_type_number_t con el tamaño en bytes.

use crate::gnumach::boolean::boolean_t;
use crate::gnumach::kern_return::kern_return_t;
use crate::gnumach::mach_types::{memory_object_name_t, memory_object_t, vm_task_t};
use crate::gnumach::message::mach_msg_type_number_t;
use crate::gnumach::vm_inherit::vm_inherit_t;
use crate::gnumach::vm_prot::vm_prot_t;
use crate::gnumach::vm_statistics::vm_statistics_data_t;
use crate::gnumach::vm_types::{pointer_t, vm_address_t, vm_offset_t, vm_size_t};

unsafe extern "C" {
    pub fn vm_allocate(target_task: vm_task_t,
                       address: *mut vm_address_t,
                       size: vm_size_t,
                       anywhere: boolean_t) -> kern_return_t;

    pub fn vm_deallocate(target_task: vm_task_t,
                         address: vm_address_t,
                         size: vm_size_t) -> kern_return_t;

    pub fn vm_protect(target_task: vm_task_t,
                      address: vm_address_t,
                      size: vm_size_t,
                      set_maximum: boolean_t,
                      new_protection: vm_prot_t) -> kern_return_t;

    pub fn vm_inherit(target_task: vm_task_t,
                      address: vm_address_t,
                      size: vm_size_t,
                      new_inheritance: vm_inherit_t) -> kern_return_t;

    /// Devuelve en *data una copia fuera de línea: liberarla con
    /// vm_deallocate(mach_task_self(), *data, *data_cnt).
    pub fn vm_read(target_task: vm_task_t,
                   address: vm_address_t,
                   size: vm_size_t,
                   data: *mut pointer_t,
                   data_cnt: *mut mach_msg_type_number_t) -> kern_return_t;

    pub fn vm_write(target_task: vm_task_t,
                    address: vm_address_t,
                    data: pointer_t,
                    data_cnt: mach_msg_type_number_t) -> kern_return_t;

    pub fn vm_copy(target_task: vm_task_t,
                   source_address: vm_address_t,
                   size: vm_size_t,
                   dest_address: vm_address_t) -> kern_return_t;

    /// *object_name recibe un derecho de envío: liberarlo con mach_port_deallocate.
    pub fn vm_region(target_task: vm_task_t,
                     address: *mut vm_address_t,
                     size: *mut vm_size_t,
                     protection: *mut vm_prot_t,
                     max_protection: *mut vm_prot_t,
                     inheritance: *mut vm_inherit_t,
                     is_shared: *mut boolean_t,
                     object_name: *mut memory_object_name_t,
                     offset: *mut vm_offset_t) -> kern_return_t;

    pub fn vm_statistics(target_task: vm_task_t,
                         vm_stats: *mut vm_statistics_data_t) -> kern_return_t;

    pub fn vm_map(target_task: vm_task_t,
                  address: *mut vm_address_t,
                  size: vm_size_t,
                  mask: vm_address_t,
                  anywhere: boolean_t,
                  memory_object: memory_object_t,
                  offset: vm_offset_t,
                  copy: boolean_t,
                  cur_protection: vm_prot_t,
                  max_protection: vm_prot_t,
                  inheritance: vm_inherit_t) -> kern_return_t;
}

//---------------------------------------------------------------------------//
// Envolturas seguras                                                        //
//---------------------------------------------------------------------------//

/// Información de la región que contiene (o sigue a) `address`.
#[derive(Clone, Copy, Debug)]
pub struct VmRegion {
    pub address: vm_address_t,
    pub size: vm_size_t,
    pub protection: vm_prot_t,
    pub max_protection: vm_prot_t,
    pub inheritance: vm_inherit_t,
    pub is_shared: bool,
    pub offset: vm_offset_t,
}

pub fn vm_region_info(task: vm_task_t, address: vm_address_t)
    -> Result<VmRegion, kern_return_t>
{
    let mut r = VmRegion { address, size: 0, protection: 0, max_protection: 0,
                           inheritance: 0, is_shared: false, offset: 0 };
    let mut shared: boolean_t = 0;
    let mut object_name: memory_object_name_t = 0;
    let err = unsafe {
        vm_region(task, &mut r.address, &mut r.size, &mut r.protection,
                  &mut r.max_protection, &mut r.inheritance, &mut shared,
                  &mut object_name, &mut r.offset)
    };
    if err != 0 { return Err(err); }
    if object_name != 0 {
        // No se expone: se libera para no perder la referencia.
        unsafe {
            crate::gnumach::port::mach_port_deallocate(
                crate::gnumach::task::mach_task_self(), object_name);
        }
    }
    r.is_shared = shared != 0;
    Ok(r)
}

pub fn vm_statistics_info(task: vm_task_t) -> Result<vm_statistics_data_t, kern_return_t> {
    let mut s = vm_statistics_data_t::default();
    let err = unsafe { vm_statistics(task, &mut s) };
    if err == 0 { Ok(s) } else { Err(err) }
}
