//===========================================================================//
// crate::gnumach::time_value                                                //
//---------------------------------------------------------------------------//
// From gnumach                                                              //
// include/mach/time_value.h                                                 //
//===========================================================================//

use std::sync::atomic::{fence, Ordering};
use crate::gnumach::vm_types::{integer_t, long_integer_t};

//---------------------------------------------------------------------------//
// Tipos                                                                     //
//---------------------------------------------------------------------------//

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct time_value_t {
    pub seconds: long_integer_t,
    pub microseconds: integer_t,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct time_value64_t {
    pub seconds: i64,
    pub nanoseconds: i64,
}

pub const TIME_MICROS_MAX: integer_t = 1_000_000;
pub const TIME_NANOS_MAX: i64 = 1_000_000_000;

/// Página de tiempo que el núcleo actualiza continuamente (dispositivo "time").
#[repr(C)]
pub struct mapped_time_value_t {
    pub seconds: integer_t,
    pub microseconds: integer_t,
    pub check_seconds: integer_t,
    pub time_value: time_value64_t,
    pub check_seconds64: i64,
    pub uptime_value: time_value64_t,
    pub check_upseconds64: i64,
}

//---------------------------------------------------------------------------//
// Funciones                                                                 //
//---------------------------------------------------------------------------//

/// Lee de forma coherente la hora de una página de tiempo mapeada.
/// Algoritmo de la documentación de GNU Mach: repetir mientras seconds
/// no coincida con check_seconds64 (el núcleo puede estar escribiendo).
///
/// # Safety
/// `mtime` debe apuntar a una página de tiempo mapeada y válida.
pub unsafe fn mapped_time_read(mtime: *const mapped_time_value_t) -> time_value64_t {
    unsafe {
        loop {
            let seconds = core::ptr::read_volatile(&raw const (*mtime).time_value.seconds);
            fence(Ordering::Acquire);
            let nanoseconds = core::ptr::read_volatile(&raw const (*mtime).time_value.nanoseconds);
            fence(Ordering::Acquire);
            if seconds == core::ptr::read_volatile(&raw const (*mtime).check_seconds64) {
                return time_value64_t { seconds, nanoseconds };
            }
        }
    }
}

/// Igual que mapped_time_read, para el tiempo desde el arranque.
///
/// # Safety
/// `mtime` debe apuntar a una página de tiempo mapeada y válida.
pub unsafe fn mapped_uptime_read(mtime: *const mapped_time_value_t) -> time_value64_t {
    unsafe {
        loop {
            let seconds = core::ptr::read_volatile(&raw const (*mtime).uptime_value.seconds);
            fence(Ordering::Acquire);
            let nanoseconds = core::ptr::read_volatile(&raw const (*mtime).uptime_value.nanoseconds);
            fence(Ordering::Acquire);
            if seconds == core::ptr::read_volatile(&raw const (*mtime).check_upseconds64) {
                return time_value64_t { seconds, nanoseconds };
            }
        }
    }
}

