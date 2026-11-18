//===================================================================================//
// rtc: translator del reloj de tiempo real (hurd/rtc) sobre rawrpc                  //
//===================================================================================//
//
// Interfaz: hurd/pioctl.defs (subsystem pioctl 140000), la que usa el ioctl de glibc
// para RTC_UIE_ON/OFF, RTC_RD_TIME y RTC_SET_TIME:
//
//   140000-140002  skip
//   140003         pioctl_rtc_uie_on    (reqport)                -> EOPNOTSUPP
//   140004         pioctl_rtc_uie_off   (reqport)                -> EOPNOTSUPP
//   140005-140008  skip
//   140009         pioctl_rtc_rd_time   (reqport; out tm: rtc_time_t)
//   140010         pioctl_rtc_set_time  (reqport; tm: rtc_time_t)
//
// rtc_time_t = struct[9] of int.

use hurd_rs::gnumach::kern_return::kern_return_t;
use hurd_rs::gnumach::error::{EBADF, EOPNOTSUPP};
use hurd_rs::gnuhurd::fcntl::{O_READ, O_WRITE};

use hurd_rs::rawtrans::wire::{Kind, Reader, Wire, WireError, WireTuple, Writer};
use hurd_rs::rawtrans::{MsgId, Peropen, RawTranslator, Services};
use crate::clock;
use crate::cmos;

pub use clock::RtcTime;
pub use cmos::Cmos;

pub const PIOCTL_SUBSYSTEM: MsgId = 140000;
pub const RTC_UIE_ON: MsgId = 140003;
pub const RTC_UIE_OFF: MsgId = 140004;
pub const RTC_RD_TIME: MsgId = 140009;
pub const RTC_SET_TIME: MsgId = 140010;

/// En el cable, RtcTime es un rtc_time_t (struct[9] of int).
impl Wire for RtcTime {
    const KIND: Kind = Kind::I32Array(9);
    fn encode(&self, w: &mut Writer<'_>) -> Result<(), WireError> {
        <[i32; 9]>::from(*self).encode(w)
    }
    fn decode(r: &mut Reader<'_>) -> Result<Self, WireError> {
        <[i32; 9]>::decode(r).map(RtcTime::from)
    }
}

impl WireTuple for RtcTime {
    fn kinds() -> Vec<Kind> {
        vec![Kind::I32Array(9)]
    }
    fn encode_all(&self, w: &mut Writer<'_>) -> Result<(), WireError> {
        self.encode(w)
    }
    fn decode_all(r: &mut Reader<'_>) -> Result<Self, WireError> {
        Self::decode(r)
    }
}

pub struct Rtc<C: Cmos> {
    cmos: C,
}

impl<C: Cmos> Rtc<C> {
    pub fn new(cmos: C) -> Self {
        Rtc { cmos }
    }

    pub fn cmos(&self) -> &C {
        &self.cmos
    }

    pub fn cmos_mut(&mut self) -> &mut C {
        &mut self.cmos
    }

    /// 3 RTC_UIE_ON: interrupción de fin de actualización, no implementada.
    pub fn uie_on(&mut self, _po: &Peropen) -> Result<(), kern_return_t> {
        Err(EOPNOTSUPP)
    }

    /// 4 RTC_UIE_OFF.
    pub fn uie_off(&mut self, _po: &Peropen) -> Result<(), kern_return_t> {
        Err(EOPNOTSUPP)
    }

    /// 9 RTC_RD_TIME: exige haber abierto con O_READ.
    pub fn rd_time(&mut self, po: &Peropen) -> Result<RtcTime, kern_return_t> {
        if !po.can_read() {
            return Err(EBADF);
        }
        clock::read_time(&mut self.cmos)
    }

    /// 10 RTC_SET_TIME: exige haber abierto con O_WRITE.
    pub fn set_time(&mut self, po: &Peropen, tm: RtcTime) -> Result<(), kern_return_t> {
        if !po.can_write() {
            return Err(EBADF);
        }
        clock::set_time(&mut self.cmos, &tm)
    }
}

impl<C: Cmos + Send + 'static> RawTranslator for Rtc<C> {
    const BASE_ID: MsgId = PIOCTL_SUBSYSTEM;
    /// trivfs_allow_open = O_READ | O_WRITE.
    const ALLOW_OPEN: i32 = O_READ | O_WRITE;

    fn services() -> Services<Self> {
        Services::new()
            .skip(3)                              // 140000-140002
            .add("rtc_uie_on", Self::uie_on)      // 140003
            .add("rtc_uie_off", Self::uie_off)    // 140004
            .skip(4)                              // 140005-140008
            .add("rtc_rd_time", Self::rd_time)    // 140009
            .add("rtc_set_time", Self::set_time)  // 140010
    }
}
