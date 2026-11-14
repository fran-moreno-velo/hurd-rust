//===========================================================================//
// crate::gnumach::message                                                   //
//---------------------------------------------------------------------------//
// From gnumach-1.8+git20250304                                              //
// include/mach/message.h                                                    //
//---------------------------------------------------------------------------//
// Mach IPC message and primitive function definitions.                      //
//===========================================================================//

use crate::gnumach::port::{
    mach_port_name_inlined_t, mach_port_name_t, mach_port_seqno_t, mach_port_t,
};
use crate::gnumach::vm_types::{natural_t, integer_t};
use crate::gnumach::boolean::boolean_t;
use crate::gnumach::kern_return::kern_return_t;
use std::ffi::c_uint;

//---------------------------------------------------------------------------//
// Extern functions                                                          //
//---------------------------------------------------------------------------//

unsafe extern "C" {
  pub fn mach_msg(
        msg:       *mut mach_msg_header_t,
        option:    mach_msg_option_t,
        send_size: mach_msg_size_t,
        recv_size: mach_msg_size_t,
        recv_name: mach_port_t,
        timeout:   mach_msg_timeout_t,
        notify:    mach_port_t,
    ) -> mach_msg_return_t;

  pub fn mach_msg_send(
        msg: *mut mach_msg_header_t
    ) -> mach_msg_return_t;

  pub fn mach_msg_destroy(
        msg: *mut mach_msg_header_t
    );

  /// glibc: recibe en `msg` usando msg->msgh_size como tamaño máximo y
  /// msg->msgh_local_port como puerto de recepción.
  pub fn mach_msg_receive(
        msg: *mut mach_msg_header_t
    ) -> mach_msg_return_t;

  /// glibc: bucle de servidor.  Recibe en `rcv_name`, llama a `demux` y envía
  /// la respuesta.  Solo vuelve si hay un error.
  pub fn mach_msg_server(
        demux:    mach_msg_demux_t,
        max_size: mach_msg_size_t,
        rcv_name: mach_port_t,
    ) -> mach_msg_return_t;

  /// glibc: como mach_msg_server, pero con opciones y tiempo de espera.
  /// Vuelve con MACH_RCV_TIMED_OUT si pasan `timeout` ms sin mensajes
  /// (cuando `option` incluye MACH_RCV_TIMEOUT).
  pub fn mach_msg_server_timeout(
        demux:    mach_msg_demux_t,
        max_size: mach_msg_size_t,
        rcv_name: mach_port_t,
        option:   mach_msg_option_t,
        timeout:  mach_msg_timeout_t,
    ) -> mach_msg_return_t;
}

/// Demultiplexor de un servidor MIG: rellena `reply` a partir de `request` y
/// devuelve TRUE si reconoce el mensaje.  Es el mismo tipo que ports_demuxer_t.
/// Un pánico dentro de esta función aborta el proceso (frontera extern "C").
pub type mach_msg_demux_t = unsafe extern "C" fn(
        request: *mut mach_msg_header_t,
        reply:   *mut mach_msg_header_t,
    ) -> boolean_t;

//---------------------------------------------------------------------------//
// Type mach_msg_timeout_t                                                   //
//---------------------------------------------------------------------------//

pub type mach_msg_timeout_t= natural_t;  
pub const MACH_MSG_TIMEOUT_NONE: mach_msg_timeout_t = 0;

//---------------------------------------------------------------------------//
// Type mach_msg_bits_t                                                      //
//---------------------------------------------------------------------------//

pub type mach_msg_bits_t = c_uint;

pub const MACH_MSGH_BITS_ZERO: mach_msg_bits_t          = 0x00000000;
pub const MACH_MSGH_BITS_REMOTE_MASK: mach_msg_bits_t   = 0x000000ff;
pub const MACH_MSGH_BITS_LOCAL_MASK: mach_msg_bits_t    = 0x0000ff00;
pub const MACH_MSGH_BITS_COMPLEX: mach_msg_bits_t       = 0x80000000u32;
pub const MACH_MSGH_BITS_CIRCULAR: mach_msg_bits_t      = 0x40000000;
pub const MACH_MSGH_BITS_COMPLEX_PORTS: mach_msg_bits_t = 0x20000000;
pub const MACH_MSGH_BITS_COMPLEX_DATA: mach_msg_bits_t  = 0x10000000;
pub const MACH_MSGH_BITS_MIGRATED: mach_msg_bits_t      = 0x08000000;
pub const MACH_MSGH_BITS_UNUSED: mach_msg_bits_t        = 0x07ff0000;

pub const MACH_MSGH_BITS_PORTS_MASK: mach_msg_bits_t =	
                    MACH_MSGH_BITS_REMOTE_MASK 
                  | MACH_MSGH_BITS_LOCAL_MASK ;

pub fn mach_msgh_bits(remote: mach_msg_bits_t, local: mach_msg_bits_t) 
         -> mach_msg_bits_t {
    (remote) | ((local) << 8)
}

pub fn mach_msgh_bits_remote(bits: mach_msg_bits_t) -> mach_msg_bits_t {
    (bits) & MACH_MSGH_BITS_REMOTE_MASK
}

pub fn mach_msgh_bits_local(bits: mach_msg_bits_t) -> mach_msg_bits_t {
    ((bits) & MACH_MSGH_BITS_LOCAL_MASK) >> 8
}

pub fn mach_msgh_bits_ports(bits: mach_msg_bits_t) -> mach_msg_bits_t {
    (bits) & MACH_MSGH_BITS_PORTS_MASK
}

pub fn mach_msgh_bits_other(bits: mach_msg_bits_t)-> mach_msg_bits_t {
    (bits) & !MACH_MSGH_BITS_PORTS_MASK
}

//---------------------------------------------------------------------------//
// Type mach_msg_size_t                                                      //
//---------------------------------------------------------------------------//
		
pub type mach_msg_size_t = c_uint;
pub const MACH_MSG_SIZE_MAX: mach_msg_size_t = !0;

//---------------------------------------------------------------------------//
// Type mach_msg_seno_t                                                      //
//---------------------------------------------------------------------------//

pub type mach_msg_seqno_t = natural_t;

//---------------------------------------------------------------------------//
// Type mach_msg_id_t                                                        //
//---------------------------------------------------------------------------//

pub type mach_msg_id_t = integer_t;

//---------------------------------------------------------------------------//
// Type mach_msg_header_t                                                    //
//---------------------------------------------------------------------------//

// On LP64 the remote/local port fields are widened to rpc_uintptr_t (union in
// the C) so the kernel can hold a kernel pointer without resizing the message;
// the port name lives in the low 32 bits.  The _pad fields mirror that union.
#[cfg(target_pointer_width = "32")]
#[repr(C)]
#[derive(Clone, Copy)]
pub struct mach_msg_header_t {
    pub msgh_bits: mach_msg_bits_t,
    pub msgh_size: mach_msg_size_t,
    pub msgh_remote_port: mach_port_t,
    pub msgh_local_port: mach_port_t,
    pub msgh_seqno: mach_port_seqno_t,
    pub msgh_id: mach_msg_id_t,
}
#[cfg(target_pointer_width = "64")]
#[repr(C, align(8))]
#[derive(Clone, Copy)]
pub struct mach_msg_header_t {
    pub msgh_bits: mach_msg_bits_t,
    pub msgh_size: mach_msg_size_t,
    pub msgh_remote_port: mach_port_t,
    pub _msgh_remote_pad: u32,
    pub msgh_local_port: mach_port_t,
    pub _msgh_local_pad: u32,
    pub msgh_seqno: mach_port_seqno_t,
    pub msgh_id: mach_msg_id_t,
}

#[cfg(target_pointer_width = "32")]
#[repr(C)]
#[derive(Clone, Copy)]
pub struct mach_msg_user_header_t {
    pub msgh_bits: mach_msg_bits_t,
    pub msgh_size: mach_msg_size_t,
    pub msgh_remote_port: mach_port_name_t,
    pub msgh_local_port: mach_port_name_t,
    pub msgh_seqno: mach_port_seqno_t,
    pub msgh_id: mach_msg_id_t,
}
#[cfg(target_pointer_width = "64")]
#[repr(C, align(8))]
#[derive(Clone, Copy)]
pub struct mach_msg_user_header_t {
    pub msgh_bits: mach_msg_bits_t,
    pub msgh_size: mach_msg_size_t,
    pub msgh_remote_port: mach_port_name_t,
    pub _msgh_remote_pad: u32,
    pub msgh_local_port: mach_port_name_t,
    pub _msgh_local_pad: u32,
    pub msgh_seqno: mach_port_seqno_t,
    pub msgh_id: mach_msg_id_t,
}

#[cfg(target_pointer_width = "32")]
const _: () = assert!(size_of::<mach_msg_header_t>() == 24);
#[cfg(target_pointer_width = "64")]
const _: () = assert!(size_of::<mach_msg_header_t>() == 32);

//---------------------------------------------------------------------------//
// Type mach_msg_kind_t                                                      //
//---------------------------------------------------------------------------//

pub type mach_msg_kind_t = mach_port_seqno_t;
pub const MACH_MSGH_KIND_NORMAL: mach_msg_kind_t =       0x00000000;
pub const MACH_MSGH_KIND_NOTIFICATION: mach_msg_kind_t = 0x00000001;

//---------------------------------------------------------------------------//
// Type mach_msg_type_name_t                                                 //
//---------------------------------------------------------------------------//

pub type mach_msg_type_name_t = u32;

pub const MACH_MSG_TYPE_UNSTRUCTURED: mach_msg_type_name_t   = 0;
pub const MACH_MSG_TYPE_BIT: mach_msg_type_name_t            = 0;
pub const MACH_MSG_TYPE_BOOLEAN: mach_msg_type_name_t        = 0;
pub const MACH_MSG_TYPE_INTEGER_16: mach_msg_type_name_t     = 1;
pub const MACH_MSG_TYPE_INTEGER_32: mach_msg_type_name_t     = 2;
pub const MACH_MSG_TYPE_CHAR: mach_msg_type_name_t           = 8;
pub const MACH_MSG_TYPE_BYTE: mach_msg_type_name_t           = 9;
pub const MACH_MSG_TYPE_INTEGER_8: mach_msg_type_name_t      = 9;
pub const MACH_MSG_TYPE_REAL: mach_msg_type_name_t           = 10;
pub const MACH_MSG_TYPE_INTEGER_64: mach_msg_type_name_t     = 11;
pub const MACH_MSG_TYPE_STRING: mach_msg_type_name_t         = 12;
pub const MACH_MSG_TYPE_STRING_C: mach_msg_type_name_t       = 12;

pub const MACH_MSG_TYPE_MOVE_RECEIVE: mach_msg_type_name_t   = 16;
pub const MACH_MSG_TYPE_MOVE_SEND: mach_msg_type_name_t      = 17;
pub const MACH_MSG_TYPE_MOVE_SEND_ONCE: mach_msg_type_name_t = 18;
pub const MACH_MSG_TYPE_COPY_SEND: mach_msg_type_name_t      = 19;
pub const MACH_MSG_TYPE_MAKE_SEND: mach_msg_type_name_t      = 20;
pub const MACH_MSG_TYPE_MAKE_SEND_ONCE: mach_msg_type_name_t = 21;

pub const MACH_MSG_TYPE_PORT_NAME: mach_msg_type_name_t      = 15;
pub const MACH_MSG_TYPE_PORT_RECEIVE: mach_msg_type_name_t   = MACH_MSG_TYPE_MOVE_RECEIVE;
pub const MACH_MSG_TYPE_PORT_SEND: mach_msg_type_name_t      = MACH_MSG_TYPE_MOVE_SEND;
pub const MACH_MSG_TYPE_PORT_SEND_ONCE: mach_msg_type_name_t = MACH_MSG_TYPE_MOVE_SEND_ONCE;

pub const MACH_MSG_TYPE_PROTECTED_PAYLOAD: mach_msg_type_name_t = 23;

pub const MACH_MSG_TYPE_LAST: mach_msg_type_name_t           = 23;
pub const MACH_MSG_TYPE_POLYMORPHIC: mach_msg_type_name_t    = !0;

pub fn mach_msg_type_port_any(x: mach_msg_type_name_t) -> bool {
  (x >= MACH_MSG_TYPE_MOVE_RECEIVE) && ( x <= MACH_MSG_TYPE_MAKE_SEND_ONCE)
}

pub fn mach_msg_type_port_any_send(x: mach_msg_type_name_t) -> bool {
  (x >= MACH_MSG_TYPE_MOVE_SEND) && ( x <= MACH_MSG_TYPE_MAKE_SEND_ONCE)
}

pub fn mach_msg_type_port_any_right(x: mach_msg_type_name_t) -> bool {
  (x >= MACH_MSG_TYPE_MOVE_RECEIVE) && ( x <= MACH_MSG_TYPE_MOVE_SEND_ONCE)
}

//---------------------------------------------------------------------------//
// Type mach_msg_type_size_t                                                 //
//---------------------------------------------------------------------------//

pub type mach_msg_type_size_t = c_uint;

//---------------------------------------------------------------------------//
// Type mach_msg_type_number_t                                               //
//---------------------------------------------------------------------------//

pub type mach_msg_type_number_t = natural_t;

//---------------------------------------------------------------------------//
// Type mach_msg_type_t                                                      //
// Type mach_msg_type_unpacked_t                                             //
//---------------------------------------------------------------------------//

#[cfg(target_pointer_width = "32")]
pub type mach_msg_type_t = u32;
#[cfg(target_pointer_width = "64")]
pub type mach_msg_type_t = u64;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct mach_msg_type_unpacked_t {
    pub msgt_name : mach_msg_type_name_t,
    pub msgt_size : mach_msg_type_size_t,
    pub msgt_number : mach_msg_type_number_t,
    pub msgt_inline : bool,
    pub msgt_longform : bool,
    pub msgt_deallocate : bool,
}

impl mach_msg_type_unpacked_t {
    #[cfg(target_pointer_width = "32")]
    pub fn pack(&self) -> mach_msg_type_t {
        assert!(self.msgt_name <= 0xFF, "msgt_name ocupa 8 bits");
        assert!(self.msgt_size <= 0xFF, "msgt_size ocupa 8 bits en i386");
        assert!(self.msgt_number <= 0xFFF, "msgt_number ocupa 12 bits en i386: usa la forma larga");
        self.msgt_name as u32
            | ((self.msgt_size as u32) & 0xFF) << 8
            | ((self.msgt_number as u32) & 0xFFF) << 16
            | (self.msgt_inline as u32) << 28
            | (self.msgt_longform as u32) << 29
            | (self.msgt_deallocate as u32) << 30
    }
    #[cfg(target_pointer_width = "64")]
    pub fn pack(&self) -> mach_msg_type_t {
        assert!(self.msgt_name <= 0xFF, "msgt_name ocupa 8 bits");
        assert!(self.msgt_size <= 0xFFFF, "msgt_size ocupa 16 bits en LP64");
        self.msgt_name as u64
            | ((self.msgt_size as u64) & 0xFFFF) << 8
            | (self.msgt_inline as u64) << 29
            | (self.msgt_longform as u64) << 30
            | (self.msgt_deallocate as u64) << 31
            | (self.msgt_number as u64) << 32
    }

    /// Operación inversa de pack(): descompone un descriptor recibido.
    #[cfg(target_pointer_width = "32")]
    pub const fn unpack(t: mach_msg_type_t) -> Self {
        mach_msg_type_unpacked_t {
            msgt_name: (t & 0xFF) as mach_msg_type_name_t,
            msgt_size: ((t >> 8) & 0xFF) as mach_msg_type_size_t,
            msgt_number: ((t >> 16) & 0xFFF) as mach_msg_type_number_t,
            msgt_inline: (t >> 28) & 1 != 0,
            msgt_longform: (t >> 29) & 1 != 0,
            msgt_deallocate: (t >> 30) & 1 != 0,
        }
    }

    /// Operación inversa de pack(): descompone un descriptor recibido.
    #[cfg(target_pointer_width = "64")]
    pub const fn unpack(t: mach_msg_type_t) -> Self {
        mach_msg_type_unpacked_t {
            msgt_name: (t & 0xFF) as mach_msg_type_name_t,
            msgt_size: ((t >> 8) & 0xFFFF) as mach_msg_type_size_t,
            msgt_number: (t >> 32) as mach_msg_type_number_t,
            msgt_inline: (t >> 29) & 1 != 0,
            msgt_longform: (t >> 30) & 1 != 0,
            msgt_deallocate: (t >> 31) & 1 != 0,
        }
    }
}

#[cfg(target_pointer_width = "32")]
pub const fn type_desc(name: u32, size: u16, number: u32) -> mach_msg_type_t {
    assert!(name <= 0xFF, "msgt_name ocupa 8 bits");
    assert!(size <= 0xFF, "msgt_size ocupa 8 bits en i386");
    assert!(number <= 0xFFF, "msgt_number ocupa 12 bits en i386: usa type_desc_long");
    name | ((size as u32) << 8) | (number << 16) | (1u32 << 28)
}
#[cfg(target_pointer_width = "64")]
pub const fn type_desc(name: u32, size: u16, number: u32) -> mach_msg_type_t {
    assert!(name <= 0xFF, "msgt_name ocupa 8 bits");
    // size: u16 ya cabe en sus 16 bits; number tiene 32 bits propios
    (name as u64) | ((size as u64) << 8) | (1u64 << 29) | ((number as u64) << 32)
}

// Descriptor largo inline (longform=1, inline=1, deallocate=0)
#[cfg(target_pointer_width = "32")]
pub const fn type_desc_long(name: u16, size: u16, number: u32) -> mach_msg_type_long_t {
    mach_msg_type_long_t { msgtl_header: (1u32 << 28) | (1u32 << 29), msgtl_name: name, msgtl_size: size, msgtl_number: number }
}
#[cfg(target_pointer_width = "64")]
pub const fn type_desc_long(name: u16, size: u16, number: u32) -> mach_msg_type_long_t {
    assert!(name <= 0xFF, "msgtl_name ocupa 8 bits en LP64");
    let bits = (name as u32) | ((size as u32) << 8) | (1u32 << 29) | (1u32 << 30);
    mach_msg_type_long_t { msgtl_bits: bits, msgtl_number: number }
}
// Descriptor largo OOL (longform=1, inline=0, deallocate=1)
#[cfg(target_pointer_width = "32")]
pub const fn type_desc_long_ool(name: u16, size: u16, number: u32) -> mach_msg_type_long_t {
    mach_msg_type_long_t { msgtl_header: (1u32 << 29) | (1u32 << 30), msgtl_name: name, msgtl_size: size, msgtl_number: number }
}
#[cfg(target_pointer_width = "64")]
pub const fn type_desc_long_ool(name: u16, size: u16, number: u32) -> mach_msg_type_long_t {
    assert!(name <= 0xFF, "msgtl_name ocupa 8 bits en LP64");
    let bits = (name as u32) | ((size as u32) << 8) | (1u32 << 30) | (1u32 << 31);
    mach_msg_type_long_t { msgtl_bits: bits, msgtl_number: number }
}
// Long OOL descriptor without deallocate (longform=1, inline=0, deallocate=0);
// used by fsys_get_children (names/controls). C only sets msgt_longform.
#[cfg(target_pointer_width = "32")]
pub const fn type_desc_long_ool_nodealloc(name: u16, size: u16, number: u32) -> mach_msg_type_long_t {
    mach_msg_type_long_t { msgtl_header: 1u32 << 29, msgtl_name: name, msgtl_size: size, msgtl_number: number }
}
#[cfg(target_pointer_width = "64")]
pub const fn type_desc_long_ool_nodealloc(name: u16, size: u16, number: u32) -> mach_msg_type_long_t {
    assert!(name <= 0xFF, "msgtl_name ocupa 8 bits en LP64");
    let bits = (name as u32) | ((size as u32) << 8) | (1u32 << 30);
    mach_msg_type_long_t { msgtl_bits: bits, msgtl_number: number }
}

//---------------------------------------------------------------------------//
// Type mach_msg_type_long_t                                                 //
//---------------------------------------------------------------------------//

// i386 wire layout (gnumach include/mach/message.h, non-LP64): an inline
// mach_msg_type_t word (inline=28, longform=29, deallocate=30) followed by
// msgtl_name/msgtl_size (16 bits each) and msgtl_number.
#[cfg(target_pointer_width = "32")]
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct mach_msg_type_long_t {
    pub msgtl_header: u32,
    pub msgtl_name: u16,
    pub msgtl_size: u16,
    pub msgtl_number: u32,
}

// LP64 wire layout: the descriptor is a single 64-bit word identical to
// mach_msg_type_t.  The first 32 bits hold msgtl_name:8, msgtl_size:16,
// msgtl_unused:5, msgtl_inline:1, msgtl_longform:1, msgtl_deallocate:1; the
// second 32 bits hold msgtl_number.  (sizeof == sizeof(mach_msg_type_t)).
#[cfg(target_pointer_width = "64")]
#[repr(C, align(8))]
#[derive(Debug, Clone, Copy)]
pub struct mach_msg_type_long_t {
    pub msgtl_bits: u32,
    pub msgtl_number: u32,
}

#[cfg(target_pointer_width = "32")]
const _: () = assert!(size_of::<mach_msg_type_long_t>() == 12);
#[cfg(target_pointer_width = "64")]
const _: () = assert!(size_of::<mach_msg_type_long_t>() == 8);
#[cfg(target_pointer_width = "64")]
const _: () = assert!(size_of::<mach_msg_type_long_t>() == size_of::<mach_msg_type_t>());

impl mach_msg_type_long_t {
    #[cfg(target_pointer_width = "32")]
    pub const fn name(&self) -> u16 { self.msgtl_name }
    #[cfg(target_pointer_width = "32")]
    pub const fn size(&self) -> u16 { self.msgtl_size }
    #[cfg(target_pointer_width = "32")]
    pub const fn number(&self) -> u32 { self.msgtl_number }
    #[cfg(target_pointer_width = "32")]
    pub const fn is_inline(&self) -> bool { (self.msgtl_header >> 28) & 1 != 0 }
    #[cfg(target_pointer_width = "32")]
    pub const fn is_longform(&self) -> bool { (self.msgtl_header >> 29) & 1 != 0 }

    #[cfg(target_pointer_width = "64")]
    pub const fn name(&self) -> u16 { (self.msgtl_bits & 0xFF) as u16 }
    #[cfg(target_pointer_width = "64")]
    pub const fn size(&self) -> u16 { ((self.msgtl_bits >> 8) & 0xFFFF) as u16 }
    #[cfg(target_pointer_width = "64")]
    pub const fn number(&self) -> u32 { self.msgtl_number }
    #[cfg(target_pointer_width = "64")]
    pub const fn is_inline(&self) -> bool { (self.msgtl_bits >> 29) & 1 != 0 }
    #[cfg(target_pointer_width = "64")]
    pub const fn is_longform(&self) -> bool { (self.msgtl_bits >> 30) & 1 != 0 }
}

// mach_msg_align: round a byte count up to a descriptor boundary.
// MACH_MSG_USER_ALIGNMENT is 4 on i386 and 8 on LP64 userland.
#[cfg(target_pointer_width = "32")]
pub const fn mach_msg_align(x: usize) -> usize { (x + 3) & !3 }
#[cfg(target_pointer_width = "64")]
pub const fn mach_msg_align(x: usize) -> usize { (x + 7) & !7 }

// Inlined port rights travel as mach_port_name_inlined_t elements, which is 4
// bytes on i386 and 8 bytes (rpc_uintptr_t) on LP64 userland.  MIG derives the
// element size in bits and the wire data delta from this type.
pub const MACH_PORT_INLINE_MSGT_SIZE: u16 = (8 * size_of::<mach_port_name_inlined_t>()) as u16;
pub const MACH_PORT_INLINE_SIZE: usize = size_of::<mach_port_name_inlined_t>();

//---------------------------------------------------------------------------//
// Type mach_msg_option_t                                                    //
//---------------------------------------------------------------------------//

pub type mach_msg_option_t = integer_t; 

pub const MACH_MSG_OPTION_NONE: mach_msg_option_t     = 0x00000000;
pub const MACH_SEND_MSG: mach_msg_option_t            = 0x00000001;
pub const MACH_RCV_MSG: mach_msg_option_t             = 0x00000002;
pub const MACH_SEND_TIMEOUT: mach_msg_option_t        = 0x00000010;
pub const MACH_SEND_NOTIFY: mach_msg_option_t         = 0x00000020;
pub const MACH_SEND_INTERRUPT: mach_msg_option_t      = 0x00000040;	
pub const MACH_SEND_CANCEL: mach_msg_option_t         = 0x00000080;
pub const MACH_RCV_TIMEOUT: mach_msg_option_t         = 0x00000100;
pub const MACH_RCV_NOTIFY:mach_msg_option_t           = 0x00000200;
pub const MACH_RCV_INTERRUPT: mach_msg_option_t       = 0x00000400;
pub const MACH_RCV_LARGE: mach_msg_option_t           = 0x00000800;
pub const MACH_SEND_ALWAYS: mach_msg_option_t         = 0x00010000;

//---------------------------------------------------------------------------//
// Type mach_msg_return_t                                                    //
//---------------------------------------------------------------------------//

pub type mach_msg_return_t = kern_return_t;

pub const MACH_MSG_SUCCESS: mach_msg_return_t         = 0x00000000;
pub const MACH_MSG_MASK: mach_msg_return_t            = 0x00003c00;
pub const MACH_MSG_IPC_SPACE: mach_msg_return_t       = 0x00002000;
pub const MACH_MSG_VM_SPACE: mach_msg_return_t        = 0x00001000;
pub const MACH_MSG_IPC_KERNEL: mach_msg_return_t      = 0x00000800;
pub const MACH_MSG_VM_KERNEL: mach_msg_return_t       = 0x00000400;

pub const MACH_SEND_IN_PROGRESS: mach_msg_return_t    = 0x10000001;
pub const MACH_SEND_INVALID_DATA: mach_msg_return_t   = 0x10000002;
pub const MACH_SEND_INVALID_DEST: mach_msg_return_t   = 0x10000003;
pub const MACH_SEND_TIMED_OUT: mach_msg_return_t      = 0x10000004;
pub const MACH_SEND_WILL_NOTIFY: mach_msg_return_t    = 0x10000005;
pub const MACH_SEND_NOTIFY_IN_PROGRESS: mach_msg_return_t = 0x10000006;
pub const MACH_SEND_INTERRUPTED: mach_msg_return_t    = 0x10000007;
pub const MACH_SEND_MSG_TOO_SMALL: mach_msg_return_t  = 0x10000008;
pub const MACH_SEND_INVALID_REPLY: mach_msg_return_t  = 0x10000009;
pub const MACH_SEND_INVALID_RIGHT: mach_msg_return_t  = 0x1000000a;
pub const MACH_SEND_INVALID_NOTIFY: mach_msg_return_t = 0x1000000b;
pub const MACH_SEND_INVALID_MEMORY: mach_msg_return_t = 0x1000000c;
pub const MACH_SEND_NO_BUFFER: mach_msg_return_t      = 0x1000000d;
pub const MACH_SEND_NO_NOTIFY: mach_msg_return_t      = 0x1000000e;
pub const MACH_SEND_INVALID_TYPE: mach_msg_return_t   = 0x1000000f;
pub const MACH_SEND_INVALID_HEADER: mach_msg_return_t = 0x10000010;

pub const MACH_RCV_IN_PROGRESS: mach_msg_return_t     = 0x10004001;
pub const MACH_RCV_INVALID_NAME: mach_msg_return_t    = 0x10004002;
pub const MACH_RCV_TIMED_OUT: mach_msg_return_t       = 0x10004003;
pub const MACH_RCV_TOO_LARGE: mach_msg_return_t       = 0x10004004;
pub const MACH_RCV_INTERRUPTED: mach_msg_return_t     = 0x10004005;
pub const MACH_RCV_PORT_CHANGED: mach_msg_return_t    = 0x10004006;
pub const MACH_RCV_INVALID_NOTIFY: mach_msg_return_t  = 0x10004007;
pub const MACH_RCV_INVALID_DATA: mach_msg_return_t    = 0x10004008;
pub const MACH_RCV_PORT_DIED: mach_msg_return_t       = 0x10004009;
pub const MACH_RCV_IN_SET: mach_msg_return_t          = 0x1000400a;
pub const MACH_RCV_HEADER_ERROR: mach_msg_return_t    = 0x1000400b;
pub const MACH_RCV_BODY_ERROR: mach_msg_return_t      = 0x1000400c;

pub const MACH_RCV_ERROR_BIT: mach_msg_return_t       = 0x00004000;


#[cfg(test)]
mod tests {
    use super::mach_msg_align;

    // #10: mach_msg_align rounds to the user descriptor boundary
    // (4 on i386 / 8 on LP64), the wire size of the OOL/inline replies.
    #[test]
    fn mach_msg_align_rounds_to_user_alignment() {
        #[cfg(target_pointer_width = "64")]
        {
            assert_eq!(mach_msg_align(0), 0);
            assert_eq!(mach_msg_align(1), 8);
            assert_eq!(mach_msg_align(7), 8);
            assert_eq!(mach_msg_align(8), 8);
            assert_eq!(mach_msg_align(9), 16);
            assert_eq!(mach_msg_align(13), 16);
        }
        #[cfg(target_pointer_width = "32")]
        {
            assert_eq!(mach_msg_align(0), 0);
            assert_eq!(mach_msg_align(1), 4);
            assert_eq!(mach_msg_align(3), 4);
            assert_eq!(mach_msg_align(4), 4);
            assert_eq!(mach_msg_align(5), 8);
            assert_eq!(mach_msg_align(9), 12);
        }
    }
}
