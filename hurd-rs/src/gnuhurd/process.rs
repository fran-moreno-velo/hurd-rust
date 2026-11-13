//===========================================================================//
// crate::gnuhurd::process                                                   //
//---------------------------------------------------------------------------//
// From github - gnuhurd                                                     //
// hurd/hurd/process.defs                                                    //
//===========================================================================//

use crate::gnumach::port::mach_port_t;
use crate::gnumach::error::mach_error_t;

//---------------------------------------------------------------------------//
// Extern functions                                                          //
//---------------------------------------------------------------------------//

unsafe extern "C" {

  pub fn getproc() -> mach_port_t;

  pub fn proc_mark_important(proc: mach_port_t) -> mach_error_t; 
}