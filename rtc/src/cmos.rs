//===================================================================================//
// rtc::cmos — acceso al chip MC146818 (reloj CMOS del PC)                           //
//===================================================================================//
//
// El chip se maneja con dos puertos de E/S: se escribe el número de registro en 0x70
// y se lee o escribe el dato en 0x71. Todo el `unsafe` de rtc está en este fichero.

/// Acceso a los registros del reloj. Separado en un trait para poder probar la lógica
/// de rtc con un chip simulado.
pub trait Cmos {
    fn read(&mut self, reg: u8) -> u8;
    fn write(&mut self, reg: u8, val: u8);
    /// Espera ~1 ms (usleep(1000) en el original).
    fn sleep_1ms(&mut self);
}

pub const CLOCK_CTL_ADDR: u16 = 0x70;
pub const CLOCK_DATA_ADDR: u16 = 0x71;

/// Chip real, por puertos de E/S. Sólo x86.
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub struct IoPortCmos {
    _private: (),
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
impl IoPortCmos {
    /// Pide al kernel permiso para usar 0x70-0x71 (ioperm de glibc, que en Hurd usa
    /// i386_io_perm_create/modify con el puerto del dispositivo maestro: hace falta
    /// ser root).
    #[cfg(target_os = "hurd")]
    pub fn acquire() -> std::io::Result<Self> {
        unsafe extern "C" {
            fn ioperm(from: core::ffi::c_ulong, num: core::ffi::c_ulong, turn_on: core::ffi::c_int)
                -> core::ffi::c_int;
        }
        // SAFETY: llamada a glibc sin punteros.
        if unsafe { ioperm(CLOCK_CTL_ADDR as _, 2, 1) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(IoPortCmos { _private: () })
    }

    /// # Safety
    /// La tarea debe tener permiso de E/S sobre 0x70 y 0x71; si no, la primera
    /// instrucción `in`/`out` provoca una excepción de protección general.
    pub unsafe fn assume_permission() -> Self {
        IoPortCmos { _private: () }
    }

    #[inline]
    unsafe fn outb(port: u16, val: u8) {
        // SAFETY: lo garantiza el llamante (permiso de E/S sobre `port`).
        unsafe { core::arch::asm!("out dx, al", in("dx") port, in("al") val, options(nomem, nostack, preserves_flags)) }
    }

    #[inline]
    unsafe fn inb(port: u16) -> u8 {
        let val: u8;
        // SAFETY: lo garantiza el llamante (permiso de E/S sobre `port`).
        unsafe { core::arch::asm!("in al, dx", out("al") val, in("dx") port, options(nomem, nostack, preserves_flags)) }
        val
    }

    /// Pausa breve entre accesos. El original usa outb_p/inb_p de glibc, que escriben
    /// además en el puerto 0x80 como retardo; aquí no se toca 0x80 porque rtc sólo
    /// pide permiso sobre 0x70-0x71.
    #[inline]
    fn io_delay() {
        for _ in 0..64 {
            core::hint::spin_loop();
        }
    }
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
impl Cmos for IoPortCmos {
    fn read(&mut self, reg: u8) -> u8 {
        // SAFETY: construir IoPortCmos exige permiso sobre 0x70-0x71.
        unsafe {
            Self::outb(CLOCK_CTL_ADDR, reg);
            Self::io_delay();
            let v = Self::inb(CLOCK_DATA_ADDR);
            Self::io_delay();
            v
        }
    }

    fn write(&mut self, reg: u8, val: u8) {
        // SAFETY: construir IoPortCmos exige permiso sobre 0x70-0x71.
        unsafe {
            Self::outb(CLOCK_CTL_ADDR, reg);
            Self::io_delay();
            Self::outb(CLOCK_DATA_ADDR, val);
            Self::io_delay();
        }
    }

    fn sleep_1ms(&mut self) {
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
}
