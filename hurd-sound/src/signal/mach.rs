//===================================================================================//
// signal::mach: timbres con mensajes Mach de solo cabecera (feature "hurd")         //
//===================================================================================//
//
// Puertos:
//   wake  receive en el cliente, send en el servidor:  servidor -> cliente
//   done  receive en el servidor, send en el cliente:  cliente  -> servidor
//
// Cada timbre es un mach_msg_header_t sin cuerpo, enviado con COPY_SEND y
// MACH_SEND_TIMEOUT = 0, así que el hilo de audio nunca se bloquea al enviar.
//
// Muerte del otro extremo:
//   - Cada receptor pide una notificación no-senders en su propio puerto: si la
//     otra tarea muere, el kernel destruye su send right y llega
//     MACH_NOTIFY_NO_SENDERS al puerto, que se traduce en Error::Disconnected.
//   - Enviar a un puerto cuyo receive ya no existe da MACH_SEND_INVALID_DEST,
//     que también es Error::Disconnected.
//
// Resolución: el plazo de mach_msg va en milisegundos y GNU Mach lo cuenta en
// ticks del reloj (≈10 ms con HZ=100).  Un plazo de un periodo de 64 frames
// (1,3 ms) se convierte en la práctica en hasta un tick.

use std::mem::{size_of, zeroed};
use std::time::Duration;

use hurd_rs::gnumach::kern_return::{kern_return_t, KERN_SUCCESS};
use hurd_rs::gnumach::message::{
    mach_msg, mach_msg_bits_t, mach_msg_header_t, mach_msg_id_t, mach_msg_option_t,
    mach_msg_size_t, mach_msgh_bits, MACH_MSG_SUCCESS, MACH_MSG_TYPE_COPY_SEND,
    MACH_MSG_TYPE_MAKE_SEND, MACH_RCV_MSG, MACH_RCV_TIMED_OUT, MACH_RCV_TIMEOUT,
    MACH_RCV_TOO_LARGE, MACH_SEND_INVALID_DEST, MACH_SEND_MSG, MACH_SEND_TIMED_OUT,
    MACH_SEND_TIMEOUT,
};
use hurd_rs::gnumach::notify::MACH_NOTIFY_NO_SENDERS;
use hurd_rs::gnumach::port::{mach_port_insert_right, mach_port_t, MACH_PORT_NULL};
use hurd_rs::gnumach::task::mach_task_self;
use hurd_rs::rawtrans::rights;

use super::{ClientSignal, ServerSignal};
use crate::{Error, Result};

/// Ids de los mensajes (arbitrarios, fuera de los rangos de MIG del Hurd).
pub const WAKE_ID: mach_msg_id_t = 0x4853_0001;
pub const DONE_ID: mach_msg_id_t = 0x4853_0002;
pub const SHUTDOWN_ID: mach_msg_id_t = 0x4853_0003;

/// Búfer de recepción.  Los timbres son solo cabecera; cabe además una
/// notificación no-senders (cabecera + tipo + mscount).
#[repr(C, align(8))]
struct RcvBuf([u8; 128]);

fn mach_err(what: &str, kr: kern_return_t) -> Error {
    Error::Backend(format!("{what}: {kr:#x}"))
}

/// Envía un timbre sin bloquear.  Ok(false) si la cola del destino está llena.
fn ring(dest: mach_port_t, id: mach_msg_id_t) -> Result<bool> {
    // SAFETY: mach_msg_header_t es POD; los rellenos de 64 bits quedan a cero.
    let mut h: mach_msg_header_t = unsafe { zeroed() };
    h.msgh_bits = mach_msgh_bits(MACH_MSG_TYPE_COPY_SEND as mach_msg_bits_t, 0);
    h.msgh_size = size_of::<mach_msg_header_t>() as mach_msg_size_t;
    h.msgh_remote_port = dest;
    h.msgh_local_port = MACH_PORT_NULL;
    h.msgh_id = id;
    // SAFETY: mensaje de solo cabecera, sin derechos ni memoria fuera de línea.
    let kr = unsafe {
        mach_msg(&mut h, MACH_SEND_MSG | MACH_SEND_TIMEOUT, h.msgh_size, 0,
                 MACH_PORT_NULL, 0, MACH_PORT_NULL)
    };
    match kr {
        MACH_MSG_SUCCESS => Ok(true),
        MACH_SEND_TIMED_OUT => Ok(false),
        MACH_SEND_INVALID_DEST => Err(Error::Disconnected),
        kr => Err(mach_err("mach_msg (envío)", kr)),
    }
}

/// Recibe un mensaje en `port`.  `timeout` None = esperar sin límite.
/// Devuelve el id, o None si vence el plazo.
fn receive(port: mach_port_t, timeout: Option<Duration>) -> Result<Option<mach_msg_id_t>> {
    let mut buf = RcvBuf([0; 128]);
    let (opt, ms): (mach_msg_option_t, u32) = match timeout {
        // Redondeo hacia arriba: 0 ms solo si el plazo ya ha vencido.
        Some(t) => (MACH_RCV_MSG | MACH_RCV_TIMEOUT,
                    t.as_micros().div_ceil(1000).min(u32::MAX as u128) as u32),
        None => (MACH_RCV_MSG, 0),
    };
    loop {
        let h = buf.0.as_mut_ptr() as *mut mach_msg_header_t;
        // SAFETY: búfer alineado de 128 bytes, tamaño pasado a mach_msg.
        let kr = unsafe { mach_msg(h, opt, 0, buf.0.len() as mach_msg_size_t, port, ms,
                                   MACH_PORT_NULL) };
        match kr {
            // SAFETY: mach_msg ha escrito una cabecera válida.
            MACH_MSG_SUCCESS => return Ok(Some(unsafe { (*h).msgh_id })),
            MACH_RCV_TIMED_OUT => return Ok(None),
            // Un mensaje extraño demasiado grande: el kernel lo ha destruido.
            MACH_RCV_TOO_LARGE => continue,
            kr => return Err(mach_err("mach_msg (recepción)", kr)),
        }
    }
}

/// Crea un receive right con un send right bajo el mismo nombre y pide la
/// notificación no-senders.  El send right es el que se entregará a la otra parte.
fn new_port() -> Result<mach_port_t> {
    let p = rights::allocate_receive().map_err(|kr| mach_err("mach_port_allocate", kr))?;
    // SAFETY: p es un receive right nuestro.
    let kr = unsafe { mach_port_insert_right(mach_task_self(), p, p, MACH_MSG_TYPE_MAKE_SEND) };
    if kr != KERN_SUCCESS {
        rights::destroy_receive(p);
        return Err(mach_err("mach_port_insert_right", kr));
    }
    if let Err(kr) = rights::request_no_senders(p) {
        rights::port_deallocate(p);
        rights::destroy_receive(p);
        return Err(mach_err("mach_port_request_notification", kr));
    }
    Ok(p)
}

//-----------------------------------------------------------------------------------//
// Servidor                                                                          //
//-----------------------------------------------------------------------------------//

pub struct MachServer {
    /// Receive right: aquí llegan los avisos de fin.
    done: mach_port_t,
    /// Send right al puerto wake del cliente.
    wake: mach_port_t,
}

impl MachServer {
    /// Toma posesión de un receive right `done` y de un send right `wake`.
    /// Así se montará en el paso 2B, cuando los derechos lleguen por RPC.
    ///
    /// # Safety
    /// Los nombres deben ser derechos de esta tarea que nadie más libere.
    pub unsafe fn from_rights(done: mach_port_t, wake: mach_port_t) -> MachServer {
        MachServer { done, wake }
    }

    /// Crea el puerto done.  Devuelve también un send right a él para el cliente.
    pub fn new_done() -> Result<(mach_port_t, mach_port_t)> {
        let p = new_port()?;
        Ok((p, p))
    }
}

impl ServerSignal for MachServer {
    fn wake(&mut self) -> Result<()> {
        match ring(self.wake, WAKE_ID)? {
            true => Ok(()),
            // Cola llena: el cliente no está recogiendo timbres.
            false => Err(Error::Backend("cola del cliente llena".into())),
        }
    }

    fn wait_done(&mut self, timeout: Duration) -> Result<bool> {
        match receive(self.done, Some(timeout))? {
            None => Ok(false),
            Some(DONE_ID) => Ok(true),
            Some(MACH_NOTIFY_NO_SENDERS) => Err(Error::Disconnected),
            // Mensaje desconocido: no cuenta como fin.
            Some(_) => Ok(false),
        }
    }
}

impl Drop for MachServer {
    fn drop(&mut self) {
        // El segmento ya tiene shutdown = 1 o lo tendrá enseguida; el timbre
        // SHUTDOWN despierta al cliente aunque no lo mire.
        let _ = ring(self.wake, SHUTDOWN_ID);
        rights::port_deallocate(self.wake);
        rights::destroy_receive(self.done);
    }
}

//-----------------------------------------------------------------------------------//
// Cliente                                                                           //
//-----------------------------------------------------------------------------------//

pub struct MachClient {
    /// Receive right: aquí llegan los despertares.
    wake: mach_port_t,
    /// Send right al puerto done del servidor.
    done: mach_port_t,
}

impl MachClient {
    /// # Safety
    /// Los nombres deben ser derechos de esta tarea que nadie más libere.
    pub unsafe fn from_rights(wake: mach_port_t, done: mach_port_t) -> MachClient {
        MachClient { wake, done }
    }

    /// Crea el puerto wake.  Devuelve (receive, send right para el servidor).
    pub fn new_wake() -> Result<(mach_port_t, mach_port_t)> {
        let p = new_port()?;
        Ok((p, p))
    }
}

impl ClientSignal for MachClient {
    fn wait_wake(&mut self) -> Result<bool> {
        loop {
            match receive(self.wake, None)? {
                Some(WAKE_ID) => return Ok(true),
                // Cierre ordenado o el servidor ha muerto.
                Some(SHUTDOWN_ID) | Some(MACH_NOTIFY_NO_SENDERS) => return Ok(false),
                _ => continue,
            }
        }
    }

    fn done(&mut self) -> Result<()> {
        match ring(self.done, DONE_ID)? {
            true => Ok(()),
            false => Err(Error::Backend("cola del servidor llena".into())),
        }
    }
}

impl Drop for MachClient {
    fn drop(&mut self) {
        rights::port_deallocate(self.done);
        rights::destroy_receive(self.wake);
    }
}

//-----------------------------------------------------------------------------------//
// Par en la misma tarea                                                             //
//-----------------------------------------------------------------------------------//

/// Servidor y cliente en hilos de la misma tarea, para probar el camino Mach en el
/// Hurd sin el protocolo de control.  Cada nombre tiene receive y send a la vez,
/// así que aquí la notificación no-senders no llega nunca: la muerte del otro
/// extremo solo se prueba con dos tareas.
pub fn pair() -> Result<(MachServer, MachClient)> {
    let (done_rcv, done_snd) = MachServer::new_done()?;
    let (wake_rcv, wake_snd) = match MachClient::new_wake() {
        Ok(p) => p,
        Err(e) => {
            rights::port_deallocate(done_snd);
            rights::destroy_receive(done_rcv);
            return Err(e);
        }
    };
    // SAFETY: derechos recién creados; cada lado libera exactamente los suyos.
    unsafe { Ok((MachServer::from_rights(done_rcv, wake_snd),
                 MachClient::from_rights(wake_rcv, done_snd))) }
}
