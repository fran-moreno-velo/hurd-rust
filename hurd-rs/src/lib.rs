#![allow(non_snake_case, non_camel_case_types, non_upper_case_globals)]
#![allow(unsafe_op_in_unsafe_fn)]

pub mod gnumach;
pub mod gnuhurd;
pub mod rawtrans;

use std::ffi::c_int;

unsafe extern "C" {
    pub fn getpid() -> c_int;
    pub fn perror(s: *const std::ffi::c_char);
}

#[macro_export]
macro_rules! debug {
    ($($arg:tt)*) => {
        if $crate::gnuhurd::trivfs::dynamic::DEBUG_ENABLED.load(::std::sync::atomic::Ordering::Relaxed) {
            ::std::eprintln!($($arg)*);
        }
    };
}
