//===================================================================================//
// cliente: DataClient                                                               //
//===================================================================================//
//
// Dos formas de usar el translator:
//   - tipada (sustituye a los stubs de usuario de MIG): set_value / get_value
//   - dinámica: describe() + call_named(), comprobando la firma en ejecución

use hurd_rs::gnumach::port::{mach_port_t, MACH_PORT_NULL};
use hurd_rs::gnuhurd::hurd::file_name_lookup;
use hurd_rs::rawtrans::rights::port_deallocate;
use hurd_rs::rawtrans::{CallError, InterfaceDesc, MsgId, RawClient};
use std::ffi::CString;
use std::io;

/// Cliente del translator dataserver. Es dueño de un send right al puerto raíz del
/// translator y lo libera al destruirse.
pub struct DataClient {
  port: mach_port_t,
}

impl RawClient for DataClient {
  fn port(&self) -> mach_port_t {
    self.port
  }
}

impl Drop for DataClient {
  fn drop(&mut self) {
    port_deallocate(self.port);
  }
}

impl DataClient {
  pub const BASE_ID: MsgId = 45000;

  /// Toma posesión de un send right ya obtenido.
  pub fn from_port(port: mach_port_t) -> Option<Self> {
    (port != MACH_PORT_NULL).then_some(DataClient { port })
  }

  pub fn set_value(&self, value: i32) -> Result<(), CallError> {
    self.call(Self::BASE_ID, value)
  }

  pub fn get_value(&self) -> Result<i32, CallError> {
    self.call(Self::BASE_ID + 1, ())
  }

  /// Uso dinámico: no necesita conocer los ids.
  pub fn set_value_dynamic(&self, value: i32) -> Result<(), CallError> {
    let iface: InterfaceDesc = self.describe()?;
    self.call_named(&iface, "set_value", value)
  }

  /// Abre el nodo donde está instalado el translator (settrans -ac /tmp/data ...).
  ///
  /// El sistema de ficheros padre ve el translator activo y le envía fsys_getroot
  /// por el puerto de control; lo que devuelve aquí file_name_lookup es el send
  /// right al puerto raíz, que es el que atiende los mensajes 45000/45001.
  ///
  /// Flags 0: no se pide lectura ni escritura (el translator no implementa io_*).
  pub fn open(path: &str) -> io::Result<Self> {
    let c = CString::new(path).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    // SAFETY: cadena terminada en NUL válida durante la llamada.
    let port = unsafe { file_name_lookup(c.as_ptr(), 0, 0) };
    DataClient::from_port(port).ok_or_else(io::Error::last_os_error)
  }
}

