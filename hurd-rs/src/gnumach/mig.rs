//===========================================================================//
// crate::gnumach::mig                                                       //
//---------------------------------------------------------------------------//
// From gnumach-1.8+git20250304                                              //
// include/mach/mig_errors.h                                                 //
//===========================================================================//

use crate::gnumach::message::{MACH_MSG_TYPE_INTEGER_32, mach_msg_header_t, mach_msg_return_t, mach_msg_type_t, mach_msg_type_unpacked_t, mach_msgh_bits, mach_msgh_bits_remote};
use crate::gnumach::port::mach_port_t;
use crate::gnumach::kern_return::kern_return_t;
use std::mem::size_of;
use std::ffi::{c_int, c_char};

//---------------------------------------------------------------------------//
// Extern functions                                                          //
//---------------------------------------------------------------------------//

unsafe extern "C" {
  pub fn mig_get_reply_port() -> mach_port_t;
  pub fn mig_put_reply_port(port: mach_port_t);
  pub fn mig_dealloc_reply_port(port: mach_port_t);
}

//---------------------------------------------------------------------------//
// MIG message errors                                                        //
//---------------------------------------------------------------------------//

pub const MIG_TYPE_ERROR: mach_msg_return_t       = -300;
pub const MIG_REPLY_MISMATCH: mach_msg_return_t   = -301;
pub const MIG_REMOTE_ERROR: mach_msg_return_t     = -302;
pub const MIG_BAD_ID: mach_msg_return_t           = -303;
pub const MIG_BAD_ARGUMENTS: mach_msg_return_t    = -304;
pub const MIG_NO_REPLY: mach_msg_return_t         = -305;
pub const MIG_EXCEPTION: mach_msg_return_t        = -306;
pub const MIG_ARRAY_TOO_LARGE: mach_msg_return_t  = -307;
pub const MIG_SERVER_DIED: mach_msg_return_t      = -308;
pub const MIG_DESTROY_REQUEST: mach_msg_return_t  = -309;

//---------------------------------------------------------------------------//
// MIG types                                                                 //
//---------------------------------------------------------------------------//

#[repr(C)]
#[allow(non_snake_case)]
#[derive(Copy,Clone)]
pub struct mig_reply_header_t {
  pub Head: mach_msg_header_t,
  pub RetCodeType: mach_msg_type_t,
  pub RetCode: kern_return_t
}

pub type mig_routine_t = Option<unsafe extern "C" fn(
  arg1: *mut mach_msg_header_t,
  arg2: *mut mach_msg_header_t)>;

#[repr(C)]
#[derive(Copy,Clone)]
pub struct mig_symtab_t {
  pub ms_routine_name: *mut c_char,
  pub ms_routine_number: c_int,
  pub ms_routine: mig_routine_t
}

pub fn type_integer_32_1() -> mach_msg_type_t {
    mach_msg_type_unpacked_t {
        msgt_name: MACH_MSG_TYPE_INTEGER_32,
        msgt_size: 32,
        msgt_number: 1,
        msgt_inline: true,
        msgt_longform: false,
        msgt_deallocate: false,
    }.pack()
}

pub fn mig_reply_header_setup(outp: &mut mig_reply_header_t, inp: &mach_msg_header_t) {
    outp.Head.msgh_bits = mach_msgh_bits(mach_msgh_bits_remote(inp.msgh_bits), 0);
    outp.Head.msgh_size = size_of::<mig_reply_header_t>() as u32;
    outp.Head.msgh_remote_port = inp.msgh_remote_port;
    outp.Head.msgh_local_port = 0;
    outp.Head.msgh_seqno = 0;
    outp.Head.msgh_id = inp.msgh_id.wrapping_add(100);
    outp.RetCodeType = type_integer_32_1();
}

pub fn mig_bad_id(outp: &mut mig_reply_header_t) {
    outp.RetCode = MIG_BAD_ID;
}