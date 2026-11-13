//===========================================================================//
// crate::gnumach::kern_return                                               //
//---------------------------------------------------------------------------//
// From gnumach-1.8+git20250304                                              //
// include/mach/kern_return.h                                                //
//===========================================================================//

use std::ffi::c_int;

//---------------------------------------------------------------------------//
// Public types                                                              //
//---------------------------------------------------------------------------//

pub type kern_return_t = c_int;

//---------------------------------------------------------------------------//
// Public constants                                                          //
//---------------------------------------------------------------------------//

pub const KERN_SUCCESS: kern_return_t                     = 0;
pub const KERN_INVALID_ADDRESS: kern_return_t             = 1;
pub const KERN_PROTECTION_FAILURE: kern_return_t          = 2;
pub const KERN_NO_SPACE: kern_return_t                    = 3;
pub const KERN_INVALID_ARGUMENT: kern_return_t            = 4;
pub const KERN_FAILURE: kern_return_t                     = 5;
pub const KERN_RESOURCE_SHORTAGE: kern_return_t           = 6;
pub const KERN_NOT_RECEIVER: kern_return_t                = 7;
pub const KERN_NO_ACCESS: kern_return_t                   = 8;
pub const KERN_MEMORY_FAILURE: kern_return_t              = 9;
pub const KERN_MEMORY_ERROR: kern_return_t                = 10;
/* pub const KERN_ALREADY_IN_SET: kern_return_t           = 11; // obsolete */
pub const KERN_NOT_IN_SET: kern_return_t                  = 12;
pub const KERN_NAME_EXISTS: kern_return_t                 = 13;
pub const KERN_ABORTED: kern_return_t                     = 14;
pub const KERN_INVALID_NAME: kern_return_t                = 15;
pub const KERN_INVALID_TASK: kern_return_t                = 16;
pub const KERN_INVALID_RIGHT: kern_return_t               = 17;
pub const KERN_INVALID_VALUE: kern_return_t               = 18;
pub const KERN_UREFS_OVERFLOW: kern_return_t              = 19;
pub const KERN_INVALID_CAPABILITY: kern_return_t          = 20;
pub const KERN_RIGHT_EXISTS: kern_return_t                = 21;
pub const KERN_INVALID_HOST: kern_return_t                = 22;
pub const KERN_MEMORY_PRESENT: kern_return_t              = 23;
pub const KERN_WRITE_PROTECTION_FAILURE: kern_return_t    = 24;
pub const KERN_TERMINATED: kern_return_t                  = 26;
pub const KERN_TIMEDOUT: kern_return_t                    = 27;
pub const KERN_INTERRUPTED: kern_return_t                 = 28;
