//===================================================================================//
// rawrpc::client — RawClient                                                        //
//===================================================================================//

use hurd_rs::gnumach::mig::{MIG_TYPE_ERROR, MIG_BAD_ID, MIG_REPLY_MISMATCH};
use hurd_rs::gnumach::kern_return::{kern_return_t, KERN_SUCCESS};
use hurd_rs::gnumach::port::{mach_port_t, MACH_PORT_NULL};
use hurd_rs::gnumach::message::MACH_MSGH_BITS_COMPLEX;
use hurd_rs::gnumach::message::mach_msg_destroy;

use super::sys::{
    self, Header, MsgBuf, MsgId, ERR_REPLY_SIZE, HEADER_SIZE,
};
use super::wire::{kinds_parse, kinds_text, Kind, Reader, Wire, WireTuple, Writer};
use super::{DESCRIBE_ID, REPLY_ID_OFFSET};

//-----------------------------------------------------------------------------------//
// Errores                                                                           //
//-----------------------------------------------------------------------------------//

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CallError {
    /// Falló mach_msg (código MACH_SEND_* / MACH_RCV_*).
    Transport(kern_return_t),
    /// El servidor respondió con RetCode != KERN_SUCCESS.
    Server(kern_return_t),
    /// Respuesta malformada (MIG_REPLY_MISMATCH, MIG_TYPE_ERROR, ...).
    Protocol(kern_return_t),
    /// Los argumentos no caben en un mensaje.
    Encode(kern_return_t),
    /// call_named: el servicio no existe en la interfaz.
    UnknownService(String),
    /// call_named: los tipos de Rust no coinciden con la firma anunciada.
    Signature { service: String, expected: String, found: String },
}

impl CallError {
    /// Código kern_return_t equivalente, para quien quiera tratarlo como MIG.
    pub fn code(&self) -> kern_return_t {
        match self {
            CallError::Transport(c)
            | CallError::Server(c)
            | CallError::Protocol(c)
            | CallError::Encode(c) => *c,
            CallError::UnknownService(_) => MIG_BAD_ID,
            CallError::Signature { .. } => MIG_TYPE_ERROR,
        }
    }
}

//-----------------------------------------------------------------------------------//
// Descripción de la interfaz remota                                                 //
//-----------------------------------------------------------------------------------//

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServiceDesc {
    pub id: MsgId,
    pub name: String,
    pub args: Vec<Kind>,
    pub rets: Vec<Kind>,
}

impl ServiceDesc {
    pub fn signature(&self) -> String {
        format!("{}({}) -> ({})", self.name, kinds_text(&self.args), kinds_text(&self.rets))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InterfaceDesc {
    pub base_id: MsgId,
    pub services: Vec<ServiceDesc>,
}

impl InterfaceDesc {
    pub fn len(&self) -> usize {
        self.services.len()
    }

    pub fn is_empty(&self) -> bool {
        self.services.is_empty()
    }

    pub fn find(&self, name: &str) -> Option<&ServiceDesc> {
        self.services.iter().find(|s| s.name == name)
    }

    /// Una línea por id; "-::" marca un id sin servicio (skip).
    fn parse(base_id: MsgId, count: u32, text: &str) -> Option<Self> {
        let lines: Vec<&str> = if text.is_empty() { Vec::new() } else { text.split('\n').collect() };
        if lines.len() != count as usize {
            return None;
        }
        let mut services = Vec::new();
        for (i, l) in lines.iter().enumerate() {
            let mut it = l.splitn(3, ':');
            let name = it.next()?.to_string();
            let args = kinds_parse(it.next()?)?;
            let rets = kinds_parse(it.next()?)?;
            if name != "-" {
                services.push(ServiceDesc { id: base_id + i as MsgId, name, args, rets });
            }
        }
        Some(InterfaceDesc { base_id, services })
    }
}

//-----------------------------------------------------------------------------------//
// Trait del cliente                                                                 //
//-----------------------------------------------------------------------------------//

pub trait RawClient {
    /// Send right al translator (p. ej. el resultado de file_name_lookup).
    fn port(&self) -> mach_port_t;

    /// Envía la petición que hay en `buf` y deja la respuesta en el mismo buffer.
    /// En Hurd usa mach_msg; se puede sobrescribir (pruebas, trazas, otro transporte).
    fn exchange(&self, buf: &mut MsgBuf) -> Result<(), kern_return_t> {
            sys::rpc(buf)
    }

    /// RPC con tipos estáticos: `args` es (), un valor o una tupla; `R` igual.
    fn call<A: WireTuple, R: WireTuple>(&self, id: MsgId, args: A) -> Result<R, CallError>
    where
        Self: Sized,
    {
        let mut buf = MsgBuf::new();
        let (size, complex) = {
            let mut w = Writer::new(&mut buf.bytes, HEADER_SIZE);
            args.encode_all(&mut w).map_err(|e| CallError::Encode(e.client_code()))?;
            w.finish().map_err(|e| CallError::Encode(e.client_code()))?
        };
        let bits = sys::request_bits() | if complex { MACH_MSGH_BITS_COMPLEX } else { 0 };
        sys::write_header(
            &mut buf.bytes,
            &Header {
                bits,
                size: size as u32,
                remote: self.port(),
                local: MACH_PORT_NULL, // lo pone el transporte (puerto de respuesta)
                seqno: 0,
                id,
            },
        );
        self.exchange(&mut buf).map_err(CallError::Transport)?;
        let res = decode_reply(&buf.bytes, id);
        // Respuesta compleja que no hemos podido aceptar: sus derechos y su memoria
        // fuera de línea son nuestros y hay que destruirlos (como los stubs MIG).
        if res.is_err() {
            if let Some(mut h) = sys::read_header(&buf.bytes) {
                if h.is_complex() {
                    h.remote = MACH_PORT_NULL;
                    sys::write_header(&mut buf.bytes, &h);
                    unsafe { mach_msg_destroy(buf.header_ptr()) };
                }
            }
        }
        res
    }

    /// Pregunta al translator su id base, número de servicios y firmas.
    /// Un translator que no use rawrpc responderá Server(MIG_BAD_ID).
    fn describe(&self) -> Result<InterfaceDesc, CallError>
    where
        Self: Sized,
    {
        let (base, count, text): (i32, u32, String) = self.call(DESCRIBE_ID, ())?;
        InterfaceDesc::parse(base, count, &text).ok_or(CallError::Protocol(MIG_TYPE_ERROR))
    }

    /// RPC por nombre: comprueba, antes de enviar nada, que los tipos de Rust
    /// coinciden con la firma anunciada por el servidor.
    fn call_named<A: WireTuple, R: WireTuple>(
        &self,
        iface: &InterfaceDesc,
        name: &str,
        args: A,
    ) -> Result<R, CallError>
    where
        Self: Sized,
    {
        let s = iface.find(name).ok_or_else(|| CallError::UnknownService(name.to_string()))?;
        if s.args != A::kinds() || s.rets != R::kinds() {
            return Err(CallError::Signature {
                service: name.to_string(),
                expected: s.signature(),
                found: format!("{}({}) -> ({})", name, kinds_text(&A::kinds()), kinds_text(&R::kinds())),
            });
        }
        self.call(s.id, args)
    }
}

fn decode_reply<R: WireTuple>(bytes: &[u8], id: MsgId) -> Result<R, CallError> {
    let rh = sys::read_header(bytes).ok_or(CallError::Protocol(MIG_TYPE_ERROR))?;
    if rh.id != id.wrapping_add(REPLY_ID_OFFSET) {
        return Err(CallError::Protocol(MIG_REPLY_MISMATCH));
    }
    let size = rh.size as usize;
    if size < ERR_REPLY_SIZE || size > bytes.len() {
        return Err(CallError::Protocol(MIG_TYPE_ERROR));
    }
    let mut r = Reader::new(&bytes[..size], HEADER_SIZE, rh.is_complex());
    let code = i32::decode(&mut r).map_err(|e| CallError::Protocol(e.client_code()))?;
    if code != KERN_SUCCESS {
        return Err(CallError::Server(code));
    }
    let out = R::decode_all(&mut r).map_err(|e| CallError::Protocol(e.client_code()))?;
    r.finish().map_err(|e| CallError::Protocol(e.client_code()))?;
    // Los datos fuera de línea ya están copiados: se libera la región recibida.
    for (addr, len) in r.take_ool_regions() {
        sys::ool_deallocate(addr, len);
    }
    Ok(out)
}
