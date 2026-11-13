use std::ffi::{c_int, c_long};

use crate::gnumach::error::mach_error_t;
use crate::gnumach::error::{EOPNOTSUPP, EMIG_BAD_ID, ENULLPTR};
use crate::gnuhurd::io::io_statbuf_t;
use crate::gnuhurd::trivfs::types::trivfs_control_t;

pub use crate::gnuhurd::mig_user::{
    file_check_access, file_chmod, file_chown, file_sync, file_utimens, file_utimes, io_stat,
};

const UTIME_NOW: c_long = -1;
const UTIME_OMIT: c_long = -2;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct timespec_t {
    pub tv_sec: c_long,
    pub tv_nsec: c_long,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct time_value_t {
    pub seconds: c_int,
    pub microseconds: c_int,
}

unsafe fn set_time(cntl: *mut trivfs_control_t, set_atime: bool) -> mach_error_t {
    if cntl.is_null() { return ENULLPTR; }
    let c = unsafe { &*cntl };
    let atime = timespec_t { tv_sec: 0, tv_nsec: if set_atime { UTIME_NOW } else { UTIME_OMIT } };
    let mtime = timespec_t { tv_sec: 0, tv_nsec: if set_atime { UTIME_OMIT } else { UTIME_NOW } };
    let mut err = file_utimens(c.underlying, atime, mtime);
    if err == EMIG_BAD_ID || err == EOPNOTSUPP {
        let mut st: io_statbuf_t = std::mem::zeroed();
        // If we cannot read the underlying stat either, propagate the original
        // error instead of setting atime/mtime to 1970 with a zeroed st.
        if io_stat(c.underlying, &mut st) != 0 { return err; }
        let (atim, mtim) = if set_atime {
            (time_value_t { seconds: st.st_atime as c_int, microseconds: (st.st_atimensec / 1000) as c_int },
             time_value_t { seconds: -1, microseconds: -1 })
        } else {
            (time_value_t { seconds: -1, microseconds: -1 },
             time_value_t { seconds: st.st_mtime as c_int, microseconds: (st.st_mtimensec / 1000) as c_int })
        };
        err = file_utimes(c.underlying, atim, mtim);
    }
    err
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn trivfs_set_atime(cnt: *mut trivfs_control_t) -> mach_error_t {
    unsafe { set_time(cnt, true) }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn trivfs_set_mtime(cntl: *mut trivfs_control_t) -> mach_error_t {
    unsafe { set_time(cntl, false) }
}