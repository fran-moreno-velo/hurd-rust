//===================================================================================//
// rtc: reloj de tiempo real (CMOS) como translator, sin trivfs                      //
//===================================================================================//
//
//   settrans -c /dev/rtc /hurd/rtc       (pasivo: arranca al primer acceso)
//   hwclock --show
//
// Como el original: pide permiso de E/S antes de responder al padre, para no decir
// "estoy listo" y salir a continuación; y termina tras 2 minutos sin mensajes, pero
// sólo si no queda ninguna apertura viva (el original sale aunque las haya).

mod clock;
mod cmos;
mod rtc;

use std::process::ExitCode;

use hurd_rs::gnumach::kern_return::KERN_SUCCESS;
use hurd_rs::gnuhurd::fcntl::O_NORW;
use hurd_rs::rawtrans::RawServer;
use cmos::IoPortCmos;
use rtc::Rtc;

const IDLE_MS: u32 = 2 * 60 * 1000;

fn main() -> ExitCode {
  let cmos = match IoPortCmos::acquire() {
    Ok(c) => c,
    Err(e) => {
      eprintln!("rtc: permiso de E/S sobre 0x70-0x71: {e}");
      return ExitCode::FAILURE;
    }
  };

  let mut server = RawServer::new(Rtc::new(cmos));
  match server.run_translator(O_NORW, Some(IDLE_MS)) {
    KERN_SUCCESS => ExitCode::SUCCESS,
    kr => {
      eprintln!("rtc: error {kr:#x} (¿se ha arrancado con settrans?)");
      ExitCode::FAILURE
    }
  }
}
