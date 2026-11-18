//===================================================================================//
// datauser_set: asigna un valor al translator dataserver                            //
//===================================================================================//
//
//   settrans -ac /tmp/data ./dataserver
//   ./datauser_set /tmp/data 48

mod dataclient;

use std::process::ExitCode;
use dataclient::DataClient;
use hurd_rs::rawtrans::CallError;

fn main() -> ExitCode {
  let args: Vec<String> = std::env::args().collect();
  let (path, value) = match args.as_slice() {
    [_, path, value] => match value.parse::<i32>() {
      Ok(v) => (path, v),
      Err(_) => {
        eprintln!("datauser_set: '{value}' is not a 32-bit integer");
        return ExitCode::from(2);
      }
    },
    _ => {
      eprintln!("uso: datauser_set NODE VALUE");
      return ExitCode::from(2);
    }
  };

  // file_name_lookup -> el FS padre hace fsys_getroot -> send right a la raíz.
  let client = match DataClient::open(path) {
    Ok(c) => c,
    Err(e) => {
      eprintln!("datauser_set: can't open {path}. {e}");
      return ExitCode::FAILURE;
    }
  };

  // Mensaje 45000 con un i32; rawrpc construye la petición y valida la respuesta.
  match client.set_value(value) {
    Ok(()) => {
      println!("Value stored: {value}");
      ExitCode::SUCCESS
    },
    Err(e) => {
      let msg = match &e {
        CallError::Server(-303) => "the node is not a dataserver (MIG_BAD_ID)".to_string(),
        CallError::Server(c) if *c > 0 => std::io::Error::from_raw_os_error(*c).to_string(),
        CallError::Transport(_) => "mach_msg failure (translator died?)".to_string(),
        other => format!("{other:?}"),
      };
      eprintln!("datauser_set: {path}: {msg} (code {:#x})", e.code());
      ExitCode::FAILURE
    }
  }
  // Al salir de main, Drop de DataClient libera el send right.
}
