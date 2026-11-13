//===================================================================================//
// datauser_get: lee el valor del translator dataserver                              //
//===================================================================================//
//
//   ./datauser_get /tmp/data        -> 48

mod dataclient;

use std::process::ExitCode;
use dataclient::DataClient;

fn main() -> ExitCode {
  let args: Vec<String> = std::env::args().collect();
  let [_, path] = args.as_slice() else {
    eprintln!("uso: datauser_get NODE");
    return ExitCode::from(2);
  };

  let client = match DataClient::open(path) {
    Ok(c) => c,
    Err(e) => {
      eprintln!("datauser_get: can't open {path}. {e}");
      return ExitCode::FAILURE;
    }
  };

  match client.get_value() {
    Ok(v) => {
      println!("Value obtained: {v}");
      ExitCode::SUCCESS
    }
    Err(e) => {
      eprintln!("datauser_get: {path}: {e:?} (code {:#x})", e.code());
      ExitCode::FAILURE
    }
  }
}
