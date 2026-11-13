//===========================================================================//
// crate::gnumach::vm_param                                                  //
//---------------------------------------------------------------------------//
// From gnumach include/mach/vm_param.h                                      //
// y glibc <mach/mach_init.h> (vm_page_size)                                 //
//===========================================================================//
// En C, PAGE_SHIFT/PAGE_SIZE vienen de <mach/machine/vm_param.h>.  Aquí se
// usa el tamaño de página que glibc obtiene del núcleo al arrancar, que es
// lo que hace el código de usuario de Hurd (vm_page_size).

use crate::gnumach::vm_types::{vm_offset_t, vm_size_t};

unsafe extern "C" {
    /// Inicializado por glibc antes de main(); no cambia después.
    static __vm_page_size: vm_size_t;
}

/// Equivalente a la macro vm_page_size de <mach/mach_init.h>.
#[inline]
pub fn vm_page_size() -> vm_size_t {
    unsafe { __vm_page_size }
}

#[inline]
fn page_mask() -> vm_offset_t {
    vm_page_size() - 1
}

/// Redondea hacia arriba al múltiplo del tamaño de página.
#[inline]
pub fn round_page(x: vm_offset_t) -> vm_offset_t {
    x.wrapping_add(page_mask()) & !page_mask()
}

/// Redondea hacia abajo al múltiplo del tamaño de página.
#[inline]
pub fn trunc_page(x: vm_offset_t) -> vm_offset_t {
    x & !page_mask()
}

#[inline]
pub fn page_aligned(x: vm_offset_t) -> bool {
    x & page_mask() == 0
}
