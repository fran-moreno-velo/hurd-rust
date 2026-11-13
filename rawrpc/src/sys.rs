//===================================================================================//
// rawrpc::sys — ABI de mensajes de GNU Mach                                         //
//===================================================================================//
//
// Formato verificado contra gnumach (include/mach/message.h) y GNU MIG (type.c,
// utils.c, cpu.sym), versiones de 2026:
//
//                        i386 (ILP32)            x86_64 (LP64)
//   mach_msg_header_t    24 bytes                32 bytes (uniones de 8 bytes)
//   mach_msg_type_t      4 bytes, número 12 bits 8 bytes: palabra de bits + msgt_number u32
//   mach_msg_type_long_t 12 bytes                = mach_msg_type_t (8 bytes)
//   complex_alignof      4                       8  (relleno de cada descriptor y dato)
//   puerto en línea      4 bytes, msgt_size 32   8 bytes (mach_port_name_inlined_t), 64
//   puntero OOL          4                       8
//
// Del crate gnumach sólo se usan los alias de tipos. La cabecera y los descriptores se
// codifican aquí: el mach_msg_header_t y el pack() del crate sólo son válidos en i386.

#![allow(non_camel_case_types)]

use hurd_rs::gnumach::kern_return::{kern_return_t, KERN_SUCCESS, KERN_FAILURE};
use hurd_rs::gnumach::port::{mach_port_t, MACH_PORT_NULL, MACH_PORT_RIGHT_RECEIVE};
use hurd_rs::gnumach::port::{mach_port_allocate, mach_port_deallocate};
use hurd_rs::gnumach::port::{mach_port_move_member, mach_port_mod_refs};
use hurd_rs::gnumach::port::mach_port_request_notification;
use hurd_rs::gnumach::message::*;
use hurd_rs::gnumach::task::mach_task_self;
use hurd_rs::gnumach::mig::{mig_get_reply_port,mig_dealloc_reply_port};
use hurd_rs::gnumach::vm_user::vm_deallocate;

/// Sólo se usa como tipo de puntero (firma de los demuxers de libports).
pub type RawHeader = hurd_rs::gnumach::message::mach_msg_header_t;
pub type MsgId = i32;

//-----------------------------------------------------------------------------------//
// Constantes (gnumach: mach/message.h, mach/mig_errors.h, mach/kern_return.h)       //
//-----------------------------------------------------------------------------------//


/// MIG: MACH_MSGH_BITS(MACH_MSGH_BITS_REPLY(bits), 0); REPLY == REMOTE.
pub fn reply_bits(request_bits: u32) -> u32 {
    mach_msgh_bits(request_bits & MACH_MSGH_BITS_REMOTE_MASK, 0)
}

/// Petición normal: send right copiado al servidor, send-once creado para la respuesta.
pub fn request_bits() -> u32 {
    mach_msgh_bits(MACH_MSG_TYPE_COPY_SEND, MACH_MSG_TYPE_MAKE_SEND_ONCE)
}

//-----------------------------------------------------------------------------------//
// Layout                                                                            //
//-----------------------------------------------------------------------------------//

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Layout {
    /// complex_alignof de MIG = sizeof(uintptr_t).
    pub align: usize,
    pub header_size: usize,
    /// Tamaño de mach_msg_type_t.
    pub desc_size: usize,
    /// Tamaño de mach_msg_type_long_t.
    pub long_desc_size: usize,
    /// Hueco de un puerto en línea (mach_port_name_inlined_t).
    pub port_slot: usize,
    /// Puntero de datos fuera de línea.
    pub ptr_size: usize,
    pub off_remote: usize,
    pub off_local: usize,
    pub off_seqno: usize,
    pub off_id: usize,
    /// Descriptor de 64 bits (msgt_size de 16 bits y msgt_number de 32).
    pub wide_desc: bool,
}

impl Layout {
    pub const I386: Layout = Layout {
        align: 4,
        header_size: 24,
        desc_size: 4,
        long_desc_size: 12,
        port_slot: 4,
        ptr_size: 4,
        off_remote: 8,
        off_local: 12,
        off_seqno: 16,
        off_id: 20,
        wide_desc: false,
    };

    pub const LP64: Layout = Layout {
        align: 8,
        header_size: 32,
        desc_size: 8,
        long_desc_size: 8,
        port_slot: 8,
        ptr_size: 8,
        off_remote: 8,
        off_local: 16,
        off_seqno: 24,
        off_id: 28,
        wide_desc: true,
    };

    #[cfg(target_pointer_width = "64")]
    pub const NATIVE: Layout = Layout::LP64;
    #[cfg(not(target_pointer_width = "64"))]
    pub const NATIVE: Layout = Layout::I386;

    /// mig_reply_header_t: cabecera + RetCodeType + RetCode, redondeado.
    pub const fn err_reply_size(&self) -> usize {
        round_up(self.header_size + self.desc_size + 4, self.align)
    }

    pub const fn port_bits(&self) -> u32 {
        (self.port_slot * 8) as u32
    }

    /// Máximo de msgt_number en un descriptor corto.
    pub const fn max_short_number(&self) -> u64 {
        if self.wide_desc { u32::MAX as u64 } else { 0xfff }
    }
}

pub const fn round_up(x: usize, a: usize) -> usize {
    x.div_ceil(a) * a
}

pub const HEADER_SIZE: usize = Layout::NATIVE.header_size;
pub const ERR_REPLY_SIZE: usize = Layout::NATIVE.err_reply_size();
pub const MSG_MAX: usize = 8192;

#[repr(C, align(8))]
pub struct MsgBuf {
    pub bytes: [u8; MSG_MAX],
}

impl MsgBuf {
    pub fn new() -> Box<Self> {
        Box::new(MsgBuf { bytes: [0; MSG_MAX] })
    }
    pub fn header_ptr(&mut self) -> *mut RawHeader {
        self.bytes.as_mut_ptr().cast()
    }
}

//-----------------------------------------------------------------------------------//
// Lectura/escritura de enteros en el buffer                                         //
//-----------------------------------------------------------------------------------//

pub fn get_u32(b: &[u8], off: usize) -> u32 {
    u32::from_ne_bytes(b[off..off + 4].try_into().unwrap())
}

pub fn put_u32(b: &mut [u8], off: usize, v: u32) {
    b[off..off + 4].copy_from_slice(&v.to_ne_bytes());
}

/// Lee un nombre de puerto de un hueco de `slot` bytes (el nombre va en los 4 bytes
/// bajos; en LP64 el resto es relleno de la unión).
pub fn get_port(b: &[u8], off: usize) -> mach_port_t {
    get_u32(b, off) as mach_port_t
}

pub fn put_port(b: &mut [u8], off: usize, slot: usize, name: mach_port_t) {
    b[off..off + slot].fill(0);
    put_u32(b, off, name as u32);
}

//-----------------------------------------------------------------------------------//
// Cabecera                                                                          //
//-----------------------------------------------------------------------------------//

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    pub bits: u32,
    pub size: u32,
    pub remote: mach_port_t,
    pub local: mach_port_t,
    pub seqno: u32,
    pub id: MsgId,
}

impl Header {
    pub fn is_complex(&self) -> bool {
        self.bits & MACH_MSGH_BITS_COMPLEX != 0
    }
}

pub fn read_header_l(l: &Layout, buf: &[u8]) -> Option<Header> {
    if buf.len() < l.header_size {
        return None;
    }
    Some(Header {
        bits: get_u32(buf, 0),
        size: get_u32(buf, 4),
        remote: get_port(buf, l.off_remote),
        local: get_port(buf, l.off_local),
        seqno: get_u32(buf, l.off_seqno),
        id: get_u32(buf, l.off_id) as MsgId,
    })
}

pub fn write_header_l(l: &Layout, buf: &mut [u8], h: &Header) {
    assert!(buf.len() >= l.header_size);
    buf[..l.header_size].fill(0);
    put_u32(buf, 0, h.bits);
    put_u32(buf, 4, h.size);
    put_port(buf, l.off_remote, l.off_local - l.off_remote, h.remote);
    put_port(buf, l.off_local, l.off_seqno - l.off_local, h.local);
    put_u32(buf, l.off_seqno, h.seqno);
    put_u32(buf, l.off_id, h.id as u32);
}

pub fn read_header(buf: &[u8]) -> Option<Header> {
    read_header_l(&Layout::NATIVE, buf)
}

pub fn write_header(buf: &mut [u8], h: &Header) {
    write_header_l(&Layout::NATIVE, buf, h)
}

//-----------------------------------------------------------------------------------//
// Descriptores de tipo                                                              //
//-----------------------------------------------------------------------------------//

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TypeDesc {
    pub name: u32,
    /// Tamaño de cada elemento, en bits.
    pub size: u32,
    pub number: u32,
    pub inline: bool,
    pub longform: bool,
    pub dealloc: bool,
}

impl TypeDesc {
    pub const fn short(name: u32, size: u32, number: u32) -> Self {
        TypeDesc { name, size, number, inline: true, longform: false, dealloc: false }
    }

    pub const fn long(name: u32, size: u32, number: u32, inline: bool) -> Self {
        TypeDesc { name, size, number, inline, longform: true, dealloc: false }
    }

    /// Bytes que ocupa en el mensaje.
    pub const fn encoded_len(&self, l: &Layout) -> usize {
        if self.longform { l.long_desc_size } else { l.desc_size }
    }

    pub fn encode(&self, l: &Layout, out: &mut [u8]) {
        let flags = |inline_bit: u32| -> u32 {
            ((self.inline as u32) << inline_bit)
                | ((self.longform as u32) << (inline_bit + 1))
                | ((self.dealloc as u32) << (inline_bit + 2))
        };
        if l.wide_desc {
            // name:8 size:16 unused:5 inline:1 longform:1 deallocate:1 | number:32
            let w0 = (self.name & 0xff) | ((self.size & 0xffff) << 8) | flags(29);
            put_u32(out, 0, w0);
            put_u32(out, 4, self.number);
        } else if !self.longform {
            // name:8 size:8 number:12 inline:1 longform:1 deallocate:1 unused:1
            let w0 = (self.name & 0xff)
                | ((self.size & 0xff) << 8)
                | ((self.number & 0xfff) << 16)
                | flags(28);
            put_u32(out, 0, w0);
        } else {
            // mach_msg_type_long_t de i386: cabecera con name/size/number a 0.
            put_u32(out, 0, flags(28));
            out[4..6].copy_from_slice(&(self.name as u16).to_ne_bytes());
            out[6..8].copy_from_slice(&(self.size as u16).to_ne_bytes());
            put_u32(out, 8, self.number);
        }
    }

    /// Decodifica en `buf[off..]`. Devuelve el descriptor y los bytes que ocupa.
    pub fn decode(l: &Layout, buf: &[u8], off: usize) -> Option<(TypeDesc, usize)> {
        if off + l.desc_size > buf.len() {
            return None;
        }
        let w0 = get_u32(buf, off);
        if l.wide_desc {
            let d = TypeDesc {
                name: w0 & 0xff,
                size: (w0 >> 8) & 0xffff,
                number: get_u32(buf, off + 4),
                inline: w0 & (1 << 29) != 0,
                longform: w0 & (1 << 30) != 0,
                dealloc: w0 & (1 << 31) != 0,
            };
            return Some((d, l.desc_size));
        }
        let inline = w0 & (1 << 28) != 0;
        let longform = w0 & (1 << 29) != 0;
        let dealloc = w0 & (1 << 30) != 0;
        if !longform {
            let d = TypeDesc {
                name: w0 & 0xff,
                size: (w0 >> 8) & 0xff,
                number: (w0 >> 16) & 0xfff,
                inline,
                longform,
                dealloc,
            };
            return Some((d, l.desc_size));
        }
        if off + l.long_desc_size > buf.len() {
            return None;
        }
        let d = TypeDesc {
            name: u16::from_ne_bytes([buf[off + 4], buf[off + 5]]) as u32,
            size: u16::from_ne_bytes([buf[off + 6], buf[off + 7]]) as u32,
            number: get_u32(buf, off + 8),
            inline,
            longform,
            dealloc,
        };
        Some((d, l.long_desc_size))
    }

    /// Bytes de datos que siguen al descriptor (sin el relleno final).
    pub fn data_len(&self, l: &Layout) -> Option<usize> {
        if !self.inline {
            return Some(l.ptr_size);
        }
        let bits = (self.number as u64).checked_mul(self.size as u64)?;
        usize::try_from(bits.div_ceil(8)).ok()
    }

    pub fn is_port(&self) -> bool {
        (MACH_MSG_TYPE_MOVE_RECEIVE..=MACH_MSG_TYPE_MAKE_SEND_ONCE).contains(&self.name)
    }
}

//-----------------------------------------------------------------------------------//
// Recursos fuera del mensaje                                                        //
//-----------------------------------------------------------------------------------//

/// Libera un derecho de envío que el receptor ya no necesita.
pub fn port_deallocate(name: mach_port_t) {
    if name == MACH_PORT_NULL {
        return;
    }
    unsafe {
        mach_port_deallocate(mach_task_self(), name);
    }
}

/// Libera memoria recibida fuera de línea.
pub fn ool_deallocate(addr: usize, size: usize) {
    if size == 0 {
        return;
    }
    unsafe {
        vm_deallocate(mach_task_self(), addr, size);
    }
}

//-----------------------------------------------------------------------------------//
// Receive rights de los objetos del servidor                                        //
//-----------------------------------------------------------------------------------//


pub mod ports {
    use super::*;
    use hurd_rs::gnumach::notify::MACH_NOTIFY_NO_SENDERS;

    /// Crea un receive right nuevo.
    pub fn allocate_receive() -> Result<mach_port_t, kern_return_t> {
        {
            let mut name = MACH_PORT_NULL;
            // SAFETY: puntero válido.
            match unsafe { mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &mut name) } {
                KERN_SUCCESS => Ok(name),
                kr => Err(kr),
            }
        }
    }

    /// Mete `port` en el port set `set` (donde escucha el bucle de servicio).
    pub fn move_member(port: mach_port_t, set: mach_port_t) -> Result<(), kern_return_t> {
        match unsafe { mach_port_move_member(mach_task_self(), port, set) } {
            KERN_SUCCESS => Ok(()),
            kr => Err(kr),
        }
    }

    /// Pide al kernel una notificación no-senders, entregada en el propio `port`,
    /// cuando desaparezca el último send right creado con MAKE_SEND (sync = 1: el
    /// primer MAKE_SEND es el de la respuesta a fsys_getroot).
    pub fn request_no_senders(port: mach_port_t) -> Result<(), kern_return_t> {
        {
            let mut previous = MACH_PORT_NULL;
            // SAFETY: puntero válido; `port` es un receive right nuestro.
            let kr = unsafe {
                mach_port_request_notification(
                    mach_task_self(), port, MACH_NOTIFY_NO_SENDERS, 1, port,
                    MACH_MSG_TYPE_MAKE_SEND_ONCE, &mut previous,
                )
            };
            if kr != KERN_SUCCESS {
                return Err(kr);
            }
            port_deallocate(previous);
            Ok(())
        }
    }

    /// Destruye el receive right (y con él los send rights que tengan los clientes).
    pub fn destroy_receive(port: mach_port_t) {
        unsafe {
            mach_port_mod_refs(mach_task_self(), port, MACH_PORT_RIGHT_RECEIVE, -1);
        }
    }
}

//-----------------------------------------------------------------------------------//
// Llamadas al sistema                                                               //
//-----------------------------------------------------------------------------------//

/// Envío + recepción sobre el mismo buffer, como los stubs de usuario de MIG.
pub fn rpc(buf: &mut MsgBuf) -> Result<(), kern_return_t> {
    let mut h = read_header(&buf.bytes).ok_or(KERN_FAILURE)?;
    // SAFETY: sin precondiciones.
    let reply = unsafe { mig_get_reply_port() };
    h.local = reply;
    write_header(&mut buf.bytes, &h);
    // SAFETY: buffer de MSG_MAX bytes alineado a 8; h.size <= MSG_MAX.
    let kr = unsafe {
        mach_msg(
            buf.header_ptr(),
            MACH_SEND_MSG | MACH_RCV_MSG,
            h.size,
            MSG_MAX as u32,
            reply,
            MACH_MSG_TIMEOUT_NONE,
            MACH_PORT_NULL,
        )
    };
    if kr != KERN_SUCCESS {
        if kr & MACH_RCV_ERROR_BIT != 0 {
            unsafe { mig_dealloc_reply_port(reply) };
        }
        return Err(kr);
    }
    Ok(())
}
