//===================================================================================//
// rawrpc::fsys — lo mínimo del protocolo fsys para instalarse con settrans          //
//===================================================================================//
//
// hurd/fsys.defs (subsystem fsys 22000):
//   fsys_startup (bootstrap; openflags: int; control_port: mach_port_send_t;
//                 out realnode: mach_port_send_t)                          22000
//   fsys_goaway  (fsys; flags: int)                                         22001
//   fsys_getroot (fsys; dotdot_node: mach_port_send_t; gen_uids: idarray_t;
//                 gen_gids: idarray_t; flags: int;
//                 out do_retry: retry_type; out retry_name: string_t;
//                 out file: mach_port_send_t)                               22002
//
// El puerto de control (sólo lo recibe el padre en fsys_startup) está en un port set;
// cada fsys_getroot crea un puerto nuevo por apertura en el mismo set (server.rs).
//
// Para comprobar permisos al abrir se usan, como cliente, dos RPC del nodo subyacente:
//   io_restrict_auth  (io.defs, 21015): (uids, gids) -> new_object: mach_port_send_t
//   file_check_access (fs.defs, 20009): () -> allowed: int

use hurd_rs::gnumach::kern_return::{kern_return_t, KERN_SUCCESS, KERN_FAILURE};
use hurd_rs::gnumach::port::{mach_port_t, MACH_PORT_NULL};
use hurd_rs::gnumach::port::{MACH_PORT_RIGHT_RECIVE, MACH_PORT_RIGHT_PORT_SET};
use hurd_rs::gnumach::port::{mach_port_allocate, mach_port_deallocate};
use hurd_rs::gnumach::port::{mach_port_move_member};
use hurd_rs::gnumach::task::{mach_task_self, task_get_bootstrap_port};
use hurd_rs::gnuhurd::types::retry_type;

use super::client::{CallError, RawClient};
use super::sys::{MsgId};
use super::wire::{FixedStr, Port};

pub const FSYS_SUBSYSTEM: MsgId = 22000;
pub const FSYS_STARTUP: MsgId = 22000;
pub const FSYS_GOAWAY: MsgId = 22001;
pub const FSYS_GETROOT: MsgId = 22002;
pub const FSYS_SYNCFS: MsgId = 22004;

pub const IO_RESTRICT_AUTH: MsgId = 21015;
pub const FILE_CHECK_ACCESS: MsgId = 20009;

/// string_t = c_string[1024].
pub type StringT = FixedStr<1024>;

/// Argumentos de fsys_getroot tal como llegan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetrootRequest {
    pub dotdot: Port,
    pub uids: Vec<u32>,
    pub gids: Vec<u32>,
    pub flags: i32,
}

/// Qué responde el translator a fsys_getroot (RawTranslator::getroot).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Getroot {
    /// Comportamiento de trivfs: comprobar modos y permisos y crear un puerto de
    /// apertura (FS_RETRY_NORMAL, nombre vacío, MAKE_SEND del puerto nuevo).
    Open,
    /// Respuesta propia: el cliente debe reintentar la búsqueda (enlaces, etc.).
    Retry { retry: retry_type, name: String, port: RetryPort },
}

/// Puerto de la respuesta Getroot::Retry. Expresa también qué pasa con dotdot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetryPort {
    /// MACH_PORT_NULL. rawrpc libera dotdot.
    Null,
    /// Se devuelve dotdot (MOVE_SEND): su derecho pasa al cliente.
    Dotdot,
    /// Otro puerto, con su disposición. rawrpc libera dotdot.
    Send(Port),
}

/// io_restrict_auth: puerto al mismo objeto con las credenciales dadas (vacías =
/// ninguna).
pub fn io_restrict_auth(node: mach_port_t, uids: &[u32], gids: &[u32]) -> Result<Port, CallError> {
    Bootstrap(node).call(IO_RESTRICT_AUTH, (uids.to_vec(), gids.to_vec()))
}

/// Petición fsys_startup sobre el puerto bootstrap. Devuelve realnode.
pub fn startup_request<C: RawClient>(
    bootstrap: &C,
    open_flags: i32,
    control: mach_port_t,
) -> Result<Port, CallError> {
    bootstrap.call(FSYS_STARTUP, (open_flags, Port::make_send(control)))
}

/// Puerto bootstrap visto como cliente.
pub struct Bootstrap(pub mach_port_t);

impl RawClient for Bootstrap {
    fn port(&self) -> mach_port_t {
        self.0
    }
}

/// Puertos de un translator arrancado con fsys_startup.
#[derive(Debug, Clone, Copy)]
pub struct TranslatorPorts {
    /// Port set: es donde se recibe.
    pub set: mach_port_t,
    pub control: mach_port_t,
    pub realnode: Port,
}

/// Arranque completo en Hurd: obtiene el bootstrap, crea el port set y el puerto de
/// control dentro de él y hace fsys_startup.
pub fn startup(open_flags: i32) -> Result<TranslatorPorts, kern_return_t> {

    let task = mach_task_self();
    let bootstrap;
    // SAFETY: llamadas a libmachuser con punteros válidos.
    match task_get_bootstrap_port(task) {
        Err(err) => return Err(err),
        Ok(x) => bootstrap = x,
    }

    if bootstrap == MACH_PORT_NULL {
        return Err(KERN_FAILURE); // no se ha arrancado con settrans
    }

    let alloc = |right: u32| -> Result<mach_port_t, kern_return_t> {
        let mut name = MACH_PORT_NULL;
        match unsafe { mach_port_allocate(task, right, &mut name) } {
            KERN_SUCCESS => Ok(name),
            kr => Err(kr),
        }
    };
    let ports = (|| {
        let set = alloc(MACH_PORT_RIGHT_PORT_SET)?;
        let control = alloc(MACH_PORT_RIGHT_RECEIVE)?;
        match unsafe { mach_port_move_member(task, control, set) } {
            KERN_SUCCESS => Ok((set, control)),
            kr => Err(kr),
        }
    })();
    let (set, control) = match ports {
        Ok(v) => v,
        Err(kr) => {
            unsafe { mach_port_deallocate(task, bootstrap) };
            return Err(kr);
        }
    };

    let res = startup_request(&Bootstrap(bootstrap), open_flags, control);
    unsafe { mach_port_deallocate(task, bootstrap) };
    match res {
        Ok(realnode) => Ok(TranslatorPorts { set, control, realnode }),
        Err(e) => Err(e.code()),
    }
}
