//===========================================================================//
// crate::gnumach::error                                                     //
//---------------------------------------------------------------------------//
// From gnumach-1.8+git20250304                                              //
// include/mach/error.h                                                      //
//===========================================================================//

use crate::gnumach::kern_return::kern_return_t;

//---------------------------------------------------------------------------//
// Public types                                                              //
//---------------------------------------------------------------------------//

//---------------------------------------------------------------------------//
// Error layout as follow (32 bits)                                          //
// HI | system(6) | subsystem(12) | code(14) | LO                            //
//---------------------------------------------------------------------------//

pub type mach_error_t = kern_return_t;

//---------------------------------------------------------------------------//
// Private functions                                                         //
//---------------------------------------------------------------------------//

const fn err_system(x: mach_error_t) -> mach_error_t {
  (x & 0x3f) << 26
}

const fn err_sub(x: mach_error_t) -> mach_error_t {
  (x & 0xfff) << 14
}

//---------------------------------------------------------------------------//
// Public functions                                                          //
//---------------------------------------------------------------------------//

pub const fn err_get_system(err: mach_error_t) -> mach_error_t {
  (err >> 26) & 0x3f
}

pub const fn err_get_sub(err: mach_error_t) -> mach_error_t {
  (err >> 14) & 0xfff
}

pub const fn err_get_code(err: mach_error_t) -> mach_error_t {
  err & 0x3fff
}

//---------------------------------------------------------------------------//
// Public constants                                                          //
//---------------------------------------------------------------------------//

pub const SYSTEM_MASK: mach_error_t = err_system(0x3f);
pub const SUB_EMASK: mach_error_t =  err_sub(0xfff);
pub const CODE_EMASK: mach_error_t = 0x3fff;

pub const ERR_SUCCESS: mach_error_t = 0;
pub const ERR_NONE: mach_error_t = 0;

pub const ERR_KERN: mach_error_t       = err_system(0x0);   /* kernel */
pub const ERR_US: mach_error_t         = err_system(0x1);   /* user space library */
pub const ERR_SERVER: mach_error_t     = err_system(0x2);   /* user space servers */
pub const ERR_IPC: mach_error_t        = err_system(0x3);   /* old ipc errors */
pub const ERR_MACH_IPC: mach_error_t   = err_system(0x4);   /* mach-ipc errors */
pub const ERR_BOOTSTRAP: mach_error_t  = err_system(0x5);   /* bootstrap errors */
pub const ERR_HURD: mach_error_t       = err_system(0x10);  /* GNU Hurd server errors */
pub const ERR_LOCAL: mach_error_t      = err_system(0x3e);  /* user defined errors */
pub const ERR_IPC_COMPAT: mach_error_t = err_system(0x3f);  /* (compatibility) mach-ipc errors */

pub const ERR_MAX_SYSTEM: mach_error_t = 0x3f;

pub const ERR_UNIX: mach_error_t = ERR_KERN | err_sub(3);

pub fn err_unix(errno: i32) -> mach_error_t {
  ERR_KERN | err_sub(3) | errno
}

//---------------------------------------------------------------------------//
// Hurd errnos (kern_return_t with the 0x40000000 "serious error" bit set)   //
//---------------------------------------------------------------------------//

pub const ESUCCESS:   kern_return_t = 0;

pub const EPERM:      kern_return_t = 0x40000001; // errno 1
pub const ENOENT:     kern_return_t = 0x40000002; // errno 2
pub const EINTR:      kern_return_t = 0x40000004; // errno 4
pub const EIO:        kern_return_t = 0x40000005; // errno 5
pub const EBADF:      kern_return_t = 0x40000009; // errno 9
pub const ENOMEM:     kern_return_t = 0x4000000c; // errno 12
pub const EACCES:     kern_return_t = 0x4000000d; // errno 13
pub const EFAULT:     kern_return_t = 0x4000000e; // errno 14 (bad address)
pub const EBUSY:      kern_return_t = 0x40000010; // errno 16
pub const EXDEV:      kern_return_t = 0x40000012; // errno 18
pub const ENOTDIR:    kern_return_t = 0x40000014; // errno 20
pub const EINVAL:     kern_return_t = 0x40000016; // errno 22
pub const EROFS:      kern_return_t = 0x4000001e; // errno 30 (read-only fs)
pub const EAGAIN:     kern_return_t = 0x40000023; // errno 35
pub const EOPNOTSUPP: kern_return_t = 0x4000002d; // errno 45
pub const ENOTEMPTY:  kern_return_t = 0x40000042; // errno 66
pub const EOVERFLOW:  kern_return_t = 0x40000073; // errno 115
pub const ENULLPTR:   kern_return_t = EFAULT;     // alias for NULL pointer


