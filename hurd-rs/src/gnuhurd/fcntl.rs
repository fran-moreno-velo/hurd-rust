use std::ffi::c_int;

pub const O_NORW:      c_int = 0x0000_0000;
pub const O_READ:      c_int = 0x0000_0001;
pub const O_WRITE:     c_int = 0x0000_0002;
pub const O_RDWR:      c_int = 0x0000_0003;
pub const O_EXEC:      c_int = 0x0000_0004;
pub const O_NONBLOCK:  c_int = 0x0000_0008;
pub const O_CREAT:     c_int = 0x0000_0010;
pub const O_EXCL:      c_int = 0x0000_0020;
pub const O_NOLINK:    c_int = 0x0000_0040;
pub const O_NOTRANS:   c_int = 0x0000_0080;
pub const O_APPEND:    c_int = 0x0000_0100;
pub const O_SYNC:      c_int = 0x0000_0400;
pub const O_TRUNC:     c_int = 0x0001_0000;
pub const O_NOFOLLOW:  c_int = 0x0010_0000;
pub const O_DIRECTORY: c_int = 0x0020_0000;
pub const O_CLOEXEC:   c_int = 0x0040_0000;

pub const O_HURD:      c_int = 0x0006_FFFF;

