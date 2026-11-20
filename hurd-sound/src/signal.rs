//===================================================================================//
// signal: despertar al cliente y saber cuándo ha terminado                          //
//===================================================================================//
//
// El audio va por memoria compartida; esto solo transporta los "timbres":
//   servidor -> cliente: "procesa el ciclo N"
//   cliente  -> servidor: "terminado"
//
// Dos implementaciones:
//   - channel: hilos del mismo proceso (pruebas en cualquier sistema).
//   - mach (feature "hurd"): mensajes Mach de solo cabecera entre tareas.

use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::time::Duration;

use crate::{Error, Result};

/// Lado servidor.
pub trait ServerSignal: Send {
    /// Despierta al cliente para que procese el ciclo ya escrito en el segmento.
    fn wake(&mut self) -> Result<()>;
    /// Espera un aviso de fin.  Ok(false) si vence el plazo.  Puede recibir avisos
    /// atrasados de ciclos anteriores: quien llama comprueba `done` en el segmento.
    fn wait_done(&mut self, timeout: Duration) -> Result<bool>;
}

/// Lado cliente.
pub trait ClientSignal: Send {
    /// Espera a que el servidor lo despierte.  Ok(false) si el servidor se ha ido.
    fn wait_wake(&mut self) -> Result<bool>;
    /// Avisa de que ha terminado el ciclo.
    fn done(&mut self) -> Result<()>;
}

//-----------------------------------------------------------------------------------//
// channel                                                                           //
//-----------------------------------------------------------------------------------//

pub struct ChannelServer { wake: Sender<()>, done: Receiver<()> }
pub struct ChannelClient { wake: Receiver<()>, done: Sender<()> }

/// Un par de extremos conectados (para clientes en hilos del mismo proceso).
pub fn channel() -> (ChannelServer, ChannelClient) {
    let (wtx, wrx) = mpsc::channel();
    let (dtx, drx) = mpsc::channel();
    (ChannelServer { wake: wtx, done: drx }, ChannelClient { wake: wrx, done: dtx })
}

impl ServerSignal for ChannelServer {
    fn wake(&mut self) -> Result<()> {
        self.wake.send(()).map_err(|_| Error::Backend("cliente desaparecido".into()))
    }
    fn wait_done(&mut self, timeout: Duration) -> Result<bool> {
        match self.done.recv_timeout(timeout) {
            Ok(()) => Ok(true),
            Err(RecvTimeoutError::Timeout) => Ok(false),
            Err(RecvTimeoutError::Disconnected) => Err(Error::Backend("cliente desaparecido".into())),
        }
    }
}

impl ClientSignal for ChannelClient {
    fn wait_wake(&mut self) -> Result<bool> {
        Ok(self.wake.recv().is_ok())
    }
    fn done(&mut self) -> Result<()> {
        self.done.send(()).map_err(|_| Error::Backend("servidor desaparecido".into()))
    }
}
