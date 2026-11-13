//===================================================================================//
// rtc::clock — lectura y escritura de la hora en el chip                            //
//===================================================================================//
//
// Traducción de rtc_S_pioctl_rtc_rd_time / rtc_S_pioctl_rtc_set_time
// (hurd/rtc/rtc-cmos_pioctl-ops.c, basado en hwclock-cmos.c de util-linux).
//
// Diferencias deliberadas con el original (cada una con su prueba):
//   1. tm_yday: el original aplica la regla de bisiesto a tm_year (años desde 1900),
//      y da 2000 como no bisiesto. Aquí se usa el año real.
//   2. Modo de 12 horas: el original trata las 12 al revés (mediodía como medianoche)
//      al leer y al escribir, y en modo binario no quita el bit PM. Aquí se sigue el
//      formato del MC146818: 12 AM = 0x12 es medianoche, 12 PM = 0x92 es mediodía.
//   3. Validación: el original no comprueba nada. Aquí rd_time devuelve EIO si el
//      chip da un mes imposible (el original indexaría fuera de la tabla), y
//      set_time devuelve EINVAL si algún campo está fuera de rango o el año no cabe
//      en la ventana 1969-2068 que usa la lectura.

use super::cmos::Cmos;
use hurd_rs::gnumach::kern_return::kern_return_t;
use hurd_rs::gnumach::error::{EBUSY, EIO, EINVAL};

pub const REG_SEC: u8 = 0;
pub const REG_MIN: u8 = 2;
pub const REG_HOUR: u8 = 4;
pub const REG_WDAY: u8 = 6;
pub const REG_MDAY: u8 = 7;
pub const REG_MON: u8 = 8;
pub const REG_YEAR: u8 = 9;
/// Registro A: bit 7 UIP (actualización en curso), bits 6-4 divisor.
pub const REG_A: u8 = 10;
/// Registro B: bit 7 SET, bit 2 DM (1 = binario), bit 1 24/12 (1 = 24 h).
pub const REG_B: u8 = 11;

const A_UIP: u8 = 0x80;
const A_DIVIDER_RESET: u8 = 0x70;
const B_SET: u8 = 0x80;
const B_BINARY: u8 = 0x04;
const B_24H: u8 = 0x02;
const HOUR_PM: u8 = 0x80;

/// Tiempo máximo esperando a que el chip termine una actualización (100 × 1 ms).
const READ_ATTEMPTS: u32 = 100;

/// struct rtc_time de hurd/rtc.h (mismo orden que struct tm).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RtcTime {
    pub tm_sec: i32,
    pub tm_min: i32,
    pub tm_hour: i32,
    pub tm_mday: i32,
    pub tm_mon: i32,
    pub tm_year: i32,
    pub tm_wday: i32,
    pub tm_yday: i32,
    pub tm_isdst: i32,
}

impl From<[i32; 9]> for RtcTime {
    fn from(a: [i32; 9]) -> Self {
        RtcTime {
            tm_sec: a[0],
            tm_min: a[1],
            tm_hour: a[2],
            tm_mday: a[3],
            tm_mon: a[4],
            tm_year: a[5],
            tm_wday: a[6],
            tm_yday: a[7],
            tm_isdst: a[8],
        }
    }
}

impl From<RtcTime> for [i32; 9] {
    fn from(t: RtcTime) -> Self {
        [t.tm_sec, t.tm_min, t.tm_hour, t.tm_mday, t.tm_mon, t.tm_year, t.tm_wday, t.tm_yday, t.tm_isdst]
    }
}

fn bcd_to_bin(v: u8) -> i32 {
    (v & 0x0f) as i32 + ((v >> 4) & 0x0f) as i32 * 10
}

/// `v` en 0..=99.
fn bin_to_bcd(v: i32) -> u8 {
    (((v / 10) << 4) | (v % 10)) as u8
}

fn is_leap(year: i32) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}

const MON_YDAY: [[i32; 13]; 2] = [
    [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334, 365],
    [0, 31, 60, 91, 121, 152, 182, 213, 244, 274, 305, 335, 366],
];

/// RTC_RD_TIME.
pub fn read_time(c: &mut impl Cmos) -> Result<RtcTime, kern_return_t> {
    // Lectura coherente: esperar a que no haya actualización en curso, leer, y dar
    // la lectura por buena si los segundos no han cambiado mientras tanto.
    let mut raw = None;
    for _ in 0..READ_ATTEMPTS {
        if c.read(REG_A) & A_UIP == 0 {
            let r = [
                c.read(REG_SEC),
                c.read(REG_MIN),
                c.read(REG_HOUR),
                c.read(REG_WDAY),
                c.read(REG_MDAY),
                c.read(REG_MON),
                c.read(REG_YEAR),
            ];
            let status = c.read(REG_B);
            if r[0] == c.read(REG_SEC) {
                raw = Some((r, status));
                break;
            }
        }
        c.sleep_1ms();
    }
    let Some(([sec, min, hour, wday, mday, mon, year], status)) = raw else {
        return Err(EBUSY);
    };

    let conv = |v: u8| if status & B_BINARY != 0 { v as i32 } else { bcd_to_bin(v) };

    let twelve_hour = status & B_24H == 0;
    let pm = twelve_hour && hour & HOUR_PM != 0;
    let hour_field = if twelve_hour { hour & !HOUR_PM } else { hour };
    let mut tm_hour = conv(hour_field);
    if twelve_hour {
        // 12 AM -> 0, 1..11 AM -> 1..11, 12 PM -> 12, 1..11 PM -> 13..23.
        tm_hour = tm_hour % 12 + if pm { 12 } else { 0 };
    }

    // Sin byte de siglo (su dirección varía entre placas): regla de X/Open,
    // 69-99 -> 1969-1999 y 00-68 -> 2000-2068.
    let mut tm_year = conv(year);
    if tm_year < 69 {
        tm_year += 100;
    }

    let tm_mon = conv(mon) - 1;
    let tm_mday = conv(mday);
    if !(0..12).contains(&tm_mon) || !(1..=31).contains(&tm_mday) {
        return Err(EIO);
    }
    let tm_yday = MON_YDAY[is_leap(tm_year + 1900) as usize][tm_mon as usize] + tm_mday - 1;

    Ok(RtcTime {
        tm_sec: conv(sec),
        tm_min: conv(min),
        tm_hour,
        tm_mday,
        tm_mon,
        tm_year,
        tm_wday: conv(wday) - 1,
        tm_yday,
        tm_isdst: -1, // el reloj no sabe si es horario de verano
    })
}

/// RTC_SET_TIME.
pub fn set_time(c: &mut impl Cmos, tm: &RtcTime) -> Result<(), kern_return_t> {
    let valid = (0..=59).contains(&tm.tm_sec)
        && (0..=59).contains(&tm.tm_min)
        && (0..=23).contains(&tm.tm_hour)
        && (1..=31).contains(&tm.tm_mday)
        && (0..=11).contains(&tm.tm_mon)
        && (0..=6).contains(&tm.tm_wday)
        && (69..=168).contains(&tm.tm_year);
    if !valid {
        return Err(EINVAL);
    }

    // Avisar al chip de que se va a poner en hora y parar el divisor.
    let save_control = c.read(REG_B);
    c.write(REG_B, save_control | B_SET);
    let save_freq_select = c.read(REG_A);
    c.write(REG_A, save_freq_select | A_DIVIDER_RESET);

    let mut hour = tm.tm_hour;
    let mut pmbit = 0u8;
    if save_control & B_24H == 0 {
        if hour >= 12 {
            pmbit = HOUR_PM;
        }
        hour %= 12;
        if hour == 0 {
            hour = 12;
        }
    }

    let enc = |v: i32| if save_control & B_BINARY != 0 { v as u8 } else { bin_to_bcd(v) };

    c.write(REG_SEC, enc(tm.tm_sec));
    c.write(REG_MIN, enc(tm.tm_min));
    c.write(REG_HOUR, enc(hour) | pmbit);
    c.write(REG_WDAY, enc(tm.tm_wday + 1));
    c.write(REG_MDAY, enc(tm.tm_mday));
    c.write(REG_MON, enc(tm.tm_mon + 1));
    c.write(REG_YEAR, enc(tm.tm_year % 100));

    // Liberar en este orden exacto: el DS12887 (clon del MC146818) no reinicia el
    // oscilador si se hace al revés (comentario de Markus Kuhn en Linux).
    c.write(REG_B, save_control);
    c.write(REG_A, save_freq_select);
    Ok(())
}
