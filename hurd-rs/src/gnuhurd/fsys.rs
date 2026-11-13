//===========================================================================//
// crate::gnuhurd::fsys                                                      //
//---------------------------------------------------------------------------//
// From github - gnuhurd                                                     //
// hurd/hurd/fsys.defs                                                       //
//===========================================================================//

use crate::gnuhurd::types::fsys_t;
use crate::gnumach::error::mach_error_t;
use crate::gnumach::kern_return::kern_return_t;
use crate::gnumach::message::mach_msg_type_name_t;
use crate::gnumach::port::mach_port_t;
use crate::gnumach::todo::mach_port_send_t;

use std::ffi::c_int;

//---------------------------------------------------------------------------//
// Extern functions                                                          //
//---------------------------------------------------------------------------//

unsafe extern "C" {

    pub fn fsys_startup(
        bootstrap: mach_port_t,
        openflags: c_int,
        control_port: mach_port_send_t,
        control_port_poly: mach_msg_type_name_t,
        realnode: *mut mach_port_send_t,
    ) -> mach_error_t;
}

unsafe extern "C" {
    pub unsafe fn fsys_goaway(fsys: fsys_t, flags: ::std::os::raw::c_int) -> kern_return_t;
}
