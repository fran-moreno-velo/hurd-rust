//===================================================================================//
// rawtrans::wire — serialización de argumentos                                        //
//===================================================================================//
//
// Cada argumento es: descriptor (mach_msg_type_t o _long_t) + datos, y el conjunto se
// rellena hasta complex_alignof (4 en i386, 8 en x86_64). Es la regla de GNU MIG
// (WriteFieldDeclPrim / itCalculateSizeInfo), no la de una struct #[repr(C)].

use super::sys::{
    self, round_up, Layout, TypeDesc,
};

use crate::gnumach::mig::{MIG_TYPE_ERROR, MIG_BAD_ARGUMENTS, MIG_ARRAY_TOO_LARGE};
use crate::gnumach::kern_return::{kern_return_t};
use crate::gnumach::port::{mach_port_t, MACH_PORT_NULL};
use crate::gnumach::message::*;

//-----------------------------------------------------------------------------------//
// Tipos soportados                                                                  //
//-----------------------------------------------------------------------------------//

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Bool,
    I32,
    U32,
    I64,
    U64,
    /// array[*:4095] of char (longitud variable, en línea).
    Str,
    /// c_string[N] (tamaño fijo; p. ej. string_t = c_string[1024]).
    FixedStr(usize),
    /// array[] of uint32_t (p. ej. idarray_t), en línea o fuera de línea.
    U32Array,
    /// Derecho de puerto.
    Port,
    /// struct[N] of int (p. ej. rtc_time_t = struct[9] of int).
    I32Array(usize),
}

impl Kind {
    pub fn tag(self) -> String {
        match self {
            Kind::Bool => "bool".into(),
            Kind::I32 => "i32".into(),
            Kind::U32 => "u32".into(),
            Kind::I64 => "i64".into(),
            Kind::U64 => "u64".into(),
            Kind::Str => "str".into(),
            Kind::FixedStr(n) => format!("cstr{n}"),
            Kind::U32Array => "u32[]".into(),
            Kind::Port => "port".into(),
            Kind::I32Array(n) => format!("i32[{n}]"),
        }
    }

    pub fn from_tag(s: &str) -> Option<Kind> {
        Some(match s {
            "bool" => Kind::Bool,
            "i32" => Kind::I32,
            "u32" => Kind::U32,
            "i64" => Kind::I64,
            "u64" => Kind::U64,
            "str" => Kind::Str,
            "u32[]" => Kind::U32Array,
            "port" => Kind::Port,
            _ if s.starts_with("i32[") && s.ends_with(']') => Kind::I32Array(s[4..s.len() - 1].parse().ok()?),
            _ => Kind::FixedStr(s.strip_prefix("cstr")?.parse().ok()?),
        })
    }
}

pub fn kinds_text(k: &[Kind]) -> String {
    k.iter().map(|k| k.tag()).collect::<Vec<_>>().join(",")
}

pub fn kinds_parse(s: &str) -> Option<Vec<Kind>> {
    if s.is_empty() {
        Some(Vec::new())
    } else {
        s.split(',').map(Kind::from_tag).collect()
    }
}

//-----------------------------------------------------------------------------------//
// Errores                                                                           //
//-----------------------------------------------------------------------------------//

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WireError {
    /// No cabe en el buffer de salida.
    Overflow,
    /// El mensaje se acaba antes de lo esperado.
    Truncated,
    /// Descriptor distinto del esperado (TypeCheck de MIG).
    BadType,
    /// Demasiados elementos para enviarlos en línea.
    TooLong,
    BadUtf8,
    /// Sobran bytes tras el último argumento.
    Trailing,
    /// Puerto o datos fuera de línea en un mensaje sin el bit COMPLEX: el kernel no
    /// los ha traducido y el valor no significa nada en este espacio de nombres.
    NotComplex,
}

impl WireError {
    /// Código del servidor (MIG usa MIG_BAD_ARGUMENTS para TypeCheck).
    pub fn server_code(self) -> kern_return_t {
        match self {
            WireError::Overflow | WireError::TooLong => MIG_ARRAY_TOO_LARGE,
            _ => MIG_BAD_ARGUMENTS,
        }
    }

    /// Código del cliente al decodificar una respuesta (MIG usa MIG_TYPE_ERROR).
    pub fn client_code(self) -> kern_return_t {
        match self {
            WireError::Overflow | WireError::TooLong => MIG_ARRAY_TOO_LARGE,
            _ => MIG_TYPE_ERROR,
        }
    }
}

//-----------------------------------------------------------------------------------//
// Writer                                                                            //
//-----------------------------------------------------------------------------------//

/// Escribe argumentos a partir de `pos`. El byte 0 de `buf` es el inicio del mensaje.
pub struct Writer<'a> {
    buf: &'a mut [u8],
    pos: usize,
    l: &'static Layout,
    complex: bool,
}

impl<'a> Writer<'a> {
    pub(crate) fn new(buf: &'a mut [u8], pos: usize) -> Self {
        Self::with_layout(&Layout::NATIVE, buf, pos)
    }

    pub fn with_layout(l: &'static Layout, buf: &'a mut [u8], pos: usize) -> Self {
        Writer { buf, pos, l, complex: false }
    }

    pub fn layout(&self) -> &'static Layout {
        self.l
    }

    pub fn pos(&self) -> usize {
        self.pos
    }

    /// El mensaje lleva puertos o memoria fuera de línea.
    pub fn mark_complex(&mut self) {
        self.complex = true;
    }

    fn pad(&mut self) -> Result<(), WireError> {
        let p = round_up(self.pos, self.l.align);
        if p > self.buf.len() {
            return Err(WireError::Overflow);
        }
        self.buf[self.pos..p].fill(0);
        self.pos = p;
        Ok(())
    }

    fn reserve(&mut self, n: usize) -> Result<&mut [u8], WireError> {
        let end = self.pos.checked_add(n).ok_or(WireError::Overflow)?;
        if end > self.buf.len() {
            return Err(WireError::Overflow);
        }
        let s = &mut self.buf[self.pos..end];
        s.fill(0);
        self.pos = end;
        Ok(s)
    }

    /// Descriptor + datos + relleno hasta complex_alignof.
    pub fn put_arg(&mut self, d: TypeDesc, data: &[u8]) -> Result<(), WireError> {
        self.pad()?;
        let l = self.l;
        d.encode(l, self.reserve(d.encoded_len(l))?);
        self.reserve(data.len())?.copy_from_slice(data);
        self.pad()
    }

    /// Descriptor de puerto + nombre en un hueco de port_slot bytes.
    pub fn put_port(&mut self, disposition: u32, name: mach_port_t) -> Result<(), WireError> {
        self.mark_complex();
        self.pad()?;
        let l = self.l;
        let d = TypeDesc::short(disposition, l.port_bits(), 1);
        d.encode(l, self.reserve(l.desc_size)?);
        let slot = self.reserve(l.port_slot)?;
        sys::put_port(slot, 0, l.port_slot, name);
        self.pad()
    }

    /// Tamaño final del mensaje y si es complejo.
    pub(crate) fn finish(mut self) -> Result<(usize, bool), WireError> {
        self.pad()?;
        Ok((self.pos, self.complex))
    }
}

//-----------------------------------------------------------------------------------//
// Reader                                                                            //
//-----------------------------------------------------------------------------------//

pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
    l: &'static Layout,
    complex: bool,
    /// Regiones fuera de línea recibidas: se liberan sólo si la RPC tiene éxito
    /// (si falla, las libera mach_msg_destroy junto con el resto del mensaje).
    ool: Vec<(usize, usize)>,
}

impl<'a> Reader<'a> {
    /// `buf` debe acabar exactamente en msgh_size.
    pub(crate) fn new(buf: &'a [u8], pos: usize, complex: bool) -> Self {
        Self::with_layout(&Layout::NATIVE, buf, pos, complex)
    }

    pub fn with_layout(l: &'static Layout, buf: &'a [u8], pos: usize, complex: bool) -> Self {
        Reader { buf, pos, l, complex, ool: Vec::new() }
    }

    pub fn layout(&self) -> &'static Layout {
        self.l
    }

    fn pad(&mut self) -> Result<(), WireError> {
        let p = round_up(self.pos, self.l.align);
        if p > self.buf.len() {
            return Err(WireError::Truncated);
        }
        self.pos = p;
        Ok(())
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], WireError> {
        let end = self.pos.checked_add(n).ok_or(WireError::Truncated)?;
        if end > self.buf.len() {
            return Err(WireError::Truncated);
        }
        let s = &self.buf[self.pos..end];
        self.pos = end;
        Ok(s)
    }

    pub fn take_desc(&mut self) -> Result<TypeDesc, WireError> {
        self.pad()?;
        let (d, n) = TypeDesc::decode(self.l, self.buf, self.pos).ok_or(WireError::Truncated)?;
        self.pos += n;
        Ok(d)
    }

    /// Datos en línea de `n` bytes y relleno.
    pub fn take_inline(&mut self, n: usize) -> Result<&'a [u8], WireError> {
        let s = self.take(n)?;
        self.pad()?;
        Ok(s)
    }

    /// Argumento con descriptor corto exacto (TypeCheck completo, como MIG).
    pub fn take_exact(&mut self, expected: TypeDesc) -> Result<&'a [u8], WireError> {
        let d = self.take_desc()?;
        if d != expected {
            return Err(WireError::BadType);
        }
        let n = d.data_len(self.l).ok_or(WireError::BadType)?;
        self.take_inline(n)
    }

    /// Lee un puntero fuera de línea y copia `len` bytes. Registra la región para
    /// liberarla al terminar con éxito.
    fn take_ool(&mut self, len: usize) -> Result<Vec<u8>, WireError> {
        if !self.complex {
            return Err(WireError::NotComplex);
        }
        let p = self.take_inline(self.l.ptr_size)?;
        let addr = if self.l.ptr_size == 8 {
            u64::from_ne_bytes(p.try_into().unwrap()) as usize
        } else {
            u32::from_ne_bytes(p.try_into().unwrap()) as usize
        };
        if len == 0 {
            return Ok(Vec::new());
        }
        if addr == 0 {
            return Err(WireError::BadType);
        }
        // SAFETY: con el bit COMPLEX, el kernel ha mapeado `len` bytes en `addr`
        // dentro de nuestra tarea al entregar el mensaje.
        let v = unsafe { std::slice::from_raw_parts(addr as *const u8, len) }.to_vec();
        self.ool.push((addr, len));
        Ok(v)
    }

    pub fn is_complex(&self) -> bool {
        self.complex
    }

    /// Comprueba que se ha consumido todo el mensaje.
    pub fn finish(&mut self) -> Result<(), WireError> {
        if round_up(self.pos, self.l.align) == self.buf.len() {
            Ok(())
        } else {
            Err(WireError::Trailing)
        }
    }

    /// Regiones fuera de línea recibidas (para liberarlas tras el éxito).
    pub(crate) fn take_ool_regions(&mut self) -> Vec<(usize, usize)> {
        std::mem::take(&mut self.ool)
    }
}

//-----------------------------------------------------------------------------------//
// Wire: un valor                                                                    //
//-----------------------------------------------------------------------------------//

pub trait Wire: Sized {
    const KIND: Kind;
    fn encode(&self, w: &mut Writer<'_>) -> Result<(), WireError>;
    fn decode(r: &mut Reader<'_>) -> Result<Self, WireError>;
}

macro_rules! wire_scalar {
    ($t:ty, $kind:expr, $mach:expr) => {
        impl Wire for $t {
            const KIND: Kind = $kind;

            fn encode(&self, w: &mut Writer<'_>) -> Result<(), WireError> {
                let d = TypeDesc::short($mach, (size_of::<$t>() * 8) as u32, 1);
                w.put_arg(d, &self.to_ne_bytes())
            }

            fn decode(r: &mut Reader<'_>) -> Result<Self, WireError> {
                let d = TypeDesc::short($mach, (size_of::<$t>() * 8) as u32, 1);
                let b = r.take_exact(d)?;
                Ok(<$t>::from_ne_bytes(b.try_into().unwrap()))
            }
        }
        wire_tuple_single!($t);
    };
}

macro_rules! wire_tuple_single {
    ($t:ty) => {
        impl WireTuple for $t {
            fn kinds() -> Vec<Kind> {
                vec![<$t as Wire>::KIND]
            }
            fn encode_all(&self, w: &mut Writer<'_>) -> Result<(), WireError> {
                self.encode(w)
            }
            fn decode_all(r: &mut Reader<'_>) -> Result<Self, WireError> {
                <$t as Wire>::decode(r)
            }
        }
    };
}

wire_scalar!(i32, Kind::I32, MACH_MSG_TYPE_INTEGER_32);
wire_scalar!(u32, Kind::U32, MACH_MSG_TYPE_INTEGER_32);
wire_scalar!(i64, Kind::I64, MACH_MSG_TYPE_INTEGER_64);
wire_scalar!(u64, Kind::U64, MACH_MSG_TYPE_INTEGER_64);

/// boolean_t de MIG: entero de 32 bits con nombre MACH_MSG_TYPE_BOOLEAN.
impl Wire for bool {
    const KIND: Kind = Kind::Bool;

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), WireError> {
        w.put_arg(TypeDesc::short(MACH_MSG_TYPE_BOOLEAN, 32, 1), &(*self as i32).to_ne_bytes())
    }

    fn decode(r: &mut Reader<'_>) -> Result<Self, WireError> {
        let b = r.take_exact(TypeDesc::short(MACH_MSG_TYPE_BOOLEAN, 32, 1))?;
        Ok(i32::from_ne_bytes(b.try_into().unwrap()) != 0)
    }
}
wire_tuple_single!(bool);

/// array[*:4095] of char: longitud variable, en línea, descriptor corto.
impl Wire for String {
    const KIND: Kind = Kind::Str;

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), WireError> {
        let b = self.as_bytes();
        if b.len() > 4095 {
            return Err(WireError::TooLong);
        }
        w.put_arg(TypeDesc::short(MACH_MSG_TYPE_CHAR, 8, b.len() as u32), b)
    }

    fn decode(r: &mut Reader<'_>) -> Result<Self, WireError> {
        let d = r.take_desc()?;
        if d.name != MACH_MSG_TYPE_CHAR || d.size != 8 || !d.inline || d.longform || d.number > 4095 {
            return Err(WireError::BadType);
        }
        let b = r.take_inline(d.number as usize)?;
        String::from_utf8(b.to_vec()).map_err(|_| WireError::BadUtf8)
    }
}
wire_tuple_single!(String);

/// c_string[N]: siempre N bytes en el mensaje, terminado en NUL si cabe.
/// string_t de Hurd es FixedStr<1024>.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FixedStr<const N: usize>(pub String);

impl<const N: usize> Wire for FixedStr<N> {
    const KIND: Kind = Kind::FixedStr(N);

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), WireError> {
        let b = self.0.as_bytes();
        if b.len() >= N || b.contains(&0) {
            return Err(WireError::TooLong);
        }
        let mut data = vec![0u8; N];
        data[..b.len()].copy_from_slice(b);
        w.put_arg(TypeDesc::short(MACH_MSG_TYPE_STRING_C, 8, N as u32), &data)
    }

    fn decode(r: &mut Reader<'_>) -> Result<Self, WireError> {
        let b = r.take_exact(TypeDesc::short(MACH_MSG_TYPE_STRING_C, 8, N as u32))?;
        let end = b.iter().position(|&c| c == 0).unwrap_or(N);
        String::from_utf8(b[..end].to_vec()).map(FixedStr).map_err(|_| WireError::BadUtf8)
    }
}

impl<const N: usize> WireTuple for FixedStr<N> {
    fn kinds() -> Vec<Kind> {
        vec![Kind::FixedStr(N)]
    }
    fn encode_all(&self, w: &mut Writer<'_>) -> Result<(), WireError> {
        self.encode(w)
    }
    fn decode_all(r: &mut Reader<'_>) -> Result<Self, WireError> {
        Self::decode(r)
    }
}

/// array[] of uint32_t (idarray_t): descriptor largo; en línea hasta 2048 bytes como
/// hace MIG, fuera de línea por encima. Al enviar sólo se usa la forma en línea.
impl Wire for Vec<u32> {
    const KIND: Kind = Kind::U32Array;

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), WireError> {
        if self.len() * 4 > 2048 {
            return Err(WireError::TooLong);
        }
        let data: Vec<u8> = self.iter().flat_map(|v| v.to_ne_bytes()).collect();
        w.put_arg(TypeDesc::long(MACH_MSG_TYPE_INTEGER_32, 32, self.len() as u32, true), &data)
    }

    fn decode(r: &mut Reader<'_>) -> Result<Self, WireError> {
        let d = r.take_desc()?;
        if d.name != MACH_MSG_TYPE_INTEGER_32 || d.size != 32 {
            return Err(WireError::BadType);
        }
        let len = (d.number as usize).checked_mul(4).ok_or(WireError::BadType)?;
        let bytes = if d.inline { r.take_inline(len)?.to_vec() } else { r.take_ool(len)? };
        Ok(bytes.chunks_exact(4).map(|c| u32::from_ne_bytes(c.try_into().unwrap())).collect())
    }
}
wire_tuple_single!(Vec<u32>);

/// struct[N] of int: un solo descriptor INTEGER_32 con msgt_number = N y los N
/// enteros seguidos (es lo que genera MIG y lo que envía el ioctl de glibc).
impl<const N: usize> Wire for [i32; N] {
    const KIND: Kind = Kind::I32Array(N);

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), WireError> {
        let data: Vec<u8> = self.iter().flat_map(|v| v.to_ne_bytes()).collect();
        w.put_arg(TypeDesc::short(MACH_MSG_TYPE_INTEGER_32, 32, N as u32), &data)
    }

    fn decode(r: &mut Reader<'_>) -> Result<Self, WireError> {
        let b = r.take_exact(TypeDesc::short(MACH_MSG_TYPE_INTEGER_32, 32, N as u32))?;
        let mut out = [0i32; N];
        for (o, c) in out.iter_mut().zip(b.chunks_exact(4)) {
            *o = i32::from_ne_bytes(c.try_into().unwrap());
        }
        Ok(out)
    }
}

impl<const N: usize> WireTuple for [i32; N] {
    fn kinds() -> Vec<Kind> {
        vec![Kind::I32Array(N)]
    }
    fn encode_all(&self, w: &mut Writer<'_>) -> Result<(), WireError> {
        self.encode(w)
    }
    fn decode_all(r: &mut Reader<'_>) -> Result<Self, WireError> {
        Self::decode(r)
    }
}

//-----------------------------------------------------------------------------------//
// Puertos                                                                           //
//-----------------------------------------------------------------------------------//

/// Un derecho de puerto en un mensaje.
///
/// Al enviar, `disposition` dice qué hace el kernel con nuestro derecho (MOVE_*,
/// COPY_SEND, MAKE_*). Al recibir, es el tipo de derecho que hemos obtenido
/// (PORT_SEND, PORT_SEND_ONCE o PORT_RECEIVE) y pasa a ser nuestro.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Port {
    pub name: mach_port_t,
    pub disposition: u32,
}

impl Port {
    pub const fn copy_send(name: mach_port_t) -> Self {
        Port { name, disposition: MACH_MSG_TYPE_COPY_SEND }
    }
    pub const fn make_send(name: mach_port_t) -> Self {
        Port { name, disposition: MACH_MSG_TYPE_MAKE_SEND }
    }
    pub const fn move_send(name: mach_port_t) -> Self {
        Port { name, disposition: MACH_MSG_TYPE_MOVE_SEND }
    }
    pub const fn make_send_once(name: mach_port_t) -> Self {
        Port { name, disposition: MACH_MSG_TYPE_MAKE_SEND_ONCE }
    }
    pub const fn move_send_once(name: mach_port_t) -> Self {
        Port { name, disposition: MACH_MSG_TYPE_MOVE_SEND_ONCE }
    }
    pub const fn move_receive(name: mach_port_t) -> Self {
        Port { name, disposition: MACH_MSG_TYPE_MOVE_RECEIVE }
    }
    pub const fn null() -> Self {
        Port::copy_send(MACH_PORT_NULL)
    }
    pub fn is_null(&self) -> bool {
        self.name == MACH_PORT_NULL
    }
}

impl Wire for Port {
    const KIND: Kind = Kind::Port;

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), WireError> {
        if !(MACH_MSG_TYPE_MOVE_RECEIVE..=MACH_MSG_TYPE_MAKE_SEND_ONCE).contains(&self.disposition) {
            return Err(WireError::BadType);
        }
        w.put_port(self.disposition, self.name)
    }

    fn decode(r: &mut Reader<'_>) -> Result<Self, WireError> {
        if !r.is_complex() {
            return Err(WireError::NotComplex);
        }
        let l = r.layout();
        let d = r.take_desc()?;
        let received = matches!(
            d.name,
            MACH_MSG_TYPE_PORT_SEND | MACH_MSG_TYPE_PORT_SEND_ONCE | MACH_MSG_TYPE_PORT_RECEIVE
        );
        if !received || d.size != l.port_bits() || d.number != 1 || !d.inline || d.longform {
            return Err(WireError::BadType);
        }
        let slot = r.take_inline(l.port_slot)?;
        Ok(Port { name: sys::get_port(slot, 0), disposition: d.name })
    }
}
wire_tuple_single!(Port);

//-----------------------------------------------------------------------------------//
// WireTuple: lista de valores (argumentos o resultados)                             //
//-----------------------------------------------------------------------------------//

pub trait WireTuple: Sized {
    fn kinds() -> Vec<Kind>;
    fn encode_all(&self, w: &mut Writer<'_>) -> Result<(), WireError>;
    fn decode_all(r: &mut Reader<'_>) -> Result<Self, WireError>;
}

impl WireTuple for () {
    fn kinds() -> Vec<Kind> {
        Vec::new()
    }
    fn encode_all(&self, _w: &mut Writer<'_>) -> Result<(), WireError> {
        Ok(())
    }
    fn decode_all(_r: &mut Reader<'_>) -> Result<Self, WireError> {
        Ok(())
    }
}

macro_rules! wire_tuple {
    ($($A:ident $i:tt),+) => {
        impl<$($A: Wire),+> WireTuple for ($($A,)+) {
            fn kinds() -> Vec<Kind> {
                vec![$($A::KIND),+]
            }
            fn encode_all(&self, w: &mut Writer<'_>) -> Result<(), WireError> {
                $(self.$i.encode(w)?;)+
                Ok(())
            }
            fn decode_all(r: &mut Reader<'_>) -> Result<Self, WireError> {
                Ok(($($A::decode(r)?,)+))
            }
        }
    };
}

wire_tuple!(A 0);
wire_tuple!(A 0, B 1);
wire_tuple!(A 0, B 1, C 2);
wire_tuple!(A 0, B 1, C 2, D 3);
