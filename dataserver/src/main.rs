//===================================================================================//
// main: dataserver sin trivfs ni libports                                           //
//===================================================================================//
//
//   settrans -ac /tmp/data ./dataserver
//   settrans -g  /tmp/data                 # fsys_goaway: termina limpiamente
//
// Enlace: sólo glibc (mach_msg, task_get_special_port, mach_port_*, vm_deallocate).

mod dataserver;

use std::process;

use crate::dataserver::Data;
use hurd_rs::gnumach::kern_return::KERN_SUCCESS;
use rawrpc::RawServer;

fn main() {
  let mut server = RawServer::new(Data::new(0));

  // fsys_startup con el padre y bucle de servicio (control y raíz en un port set).
  let kr = server.run_translator(0, None);

  if kr != KERN_SUCCESS {
    eprintln!("dataserver: error {kr:#x}");
    process::exit(1);
  }
}
