#![allow(unsafe_op_in_unsafe_fn, dead_code, private_interfaces)]

use std::ffi::{c_int, c_uint, c_char};
use std::mem::{size_of, transmute};
use std::panic::{catch_unwind, AssertUnwindSafe};
use crate::gnuhurd::io::{loff_t, io_statbuf_t};
use crate::gnumach::message::type_desc;
use crate::gnumach::message::{
    mach_msg_header_t, mach_msg_type_t, mach_msg_type_long_t, mach_msg_type_name_t,
    mach_msg_type_number_t, MACH_MSG_TYPE_PROTECTED_PAYLOAD, MACH_MSG_TYPE_INTEGER_32,
    MACH_MSG_TYPE_INTEGER_64, MACH_MSG_TYPE_STRING_C, MACH_MSG_TYPE_PORT_SEND,
    MACH_MSG_TYPE_CHAR, MACH_MSGH_BITS_COMPLEX, mach_msgh_bits_local,
    mach_msgh_bits_remote, mach_msg_type_port_any_right, type_desc_long,
    type_desc_long_ool, MACH_PORT_INLINE_MSGT_SIZE, mach_msg_align,
};
use crate::gnumach::mig::{
    mig_reply_header_t, mig_reply_header_setup, mig_bad_id, MIG_BAD_ARGUMENTS,
};
use crate::gnumach::port::mach_port_t;
use crate::gnumach::kern_return::{kern_return_t, KERN_SUCCESS};
use crate::gnumach::error::EOPNOTSUPP;
use crate::gnumach::boolean::boolean_t;
use crate::gnuhurd::trivfs::types::trivfs_protid_t;
use crate::gnuhurd::trivfs::mig_helpers::{
    trivfs_begin_using_protid, trivfs_begin_using_protid_payload, ProtidGuard,
};
use crate::gnuhurd::trivfs::io_handlers::{
    trivfs_S_io_revoke, trivfs_S_io_stat, trivfs_S_io_write, trivfs_S_io_read,
};
use crate::gnuhurd::trivfs::ioctl::{
    trivfs_S_io_clear_some_openmodes, trivfs_S_io_get_openmodes, trivfs_S_io_readable,
    trivfs_S_io_set_all_openmodes, trivfs_S_io_set_some_openmodes,
    trivfs_S_io_select, trivfs_S_io_seek, trivfs_S_io_select_timeout,
};
use crate::gnuhurd::trivfs::io_stubs::{
    trivfs_S_io_async, trivfs_S_io_eofnotify, trivfs_S_io_get_conch,
    trivfs_S_io_get_icky_async_id, trivfs_S_io_get_owner, trivfs_S_io_map,
    trivfs_S_io_map_cntl, trivfs_S_io_mod_owner, trivfs_S_io_postnotify,
    trivfs_S_io_prenotify, trivfs_S_io_readnotify, trivfs_S_io_readsleep,
    trivfs_S_io_release_conch, trivfs_S_io_sigio, trivfs_S_io_pathconf,
    trivfs_S_io_duplicate, trivfs_S_io_identity, trivfs_S_io_restrict_auth,
    trivfs_S_io_reauthenticate, trivfs_S_io_server_version,
};
use crate::gnumach::vm_types::{vm_offset_t, vm_size_t};

//---------------------------------------------------------------------------//
// Type-descriptor constants                                                 //
//---------------------------------------------------------------------------//
pub const T_INTEGER_32_1: mach_msg_type_t = type_desc(MACH_MSG_TYPE_INTEGER_32, 32, 1);
pub const T_INTEGER_32_2: mach_msg_type_t = type_desc(MACH_MSG_TYPE_INTEGER_32, 32, 2);
pub const T_INTEGER_64_1: mach_msg_type_t = type_desc(MACH_MSG_TYPE_INTEGER_64, 64, 1);
pub const T_STRING_C_1024: mach_msg_type_t = type_desc(MACH_MSG_TYPE_STRING_C, 8, 1024);
pub const T_PORT_SEND_1: mach_msg_type_t = type_desc(MACH_MSG_TYPE_PORT_SEND, MACH_PORT_INLINE_MSGT_SIZE, 1);
pub const T_POLY_1: mach_msg_type_t = type_desc(0xFF, MACH_PORT_INLINE_MSGT_SIZE, 1);
// vm_offset_t/vm_size_t = uintptr_t: 4B (i386) / 8B (amd64)
#[cfg(target_pointer_width = "32")]
pub const T_VM_OFFSET_1: mach_msg_type_t = T_INTEGER_32_1;
#[cfg(target_pointer_width = "64")]
pub const T_VM_OFFSET_1: mach_msg_type_t = T_INTEGER_64_1;
// timespec_t = {long,long}: 2×32 (i386) / 2×64 (amd64)
#[cfg(target_pointer_width = "32")]
pub const T_TIMESPEC: mach_msg_type_t = T_INTEGER_32_2;
#[cfg(target_pointer_width = "64")]
pub const T_TIMESPEC: mach_msg_type_t = type_desc(MACH_MSG_TYPE_INTEGER_64, 64, 2);

// _Xio_* routine types (C: mig_routine_t = void(*)(header*, header*)).
// We will used in trivfs_io_server_routines[] table (Step C).
pub type io_server_routine = unsafe extern "C-unwind" fn(
    inp: *mut mach_msg_header_t,
    outp: *mut mach_msg_header_t,
);

pub fn begin_using_io(bits: u32, port: mach_port_t) -> *mut trivfs_protid_t {
    if mach_msgh_bits_local(bits) == MACH_MSG_TYPE_PROTECTED_PAYLOAD {
        trivfs_begin_using_protid_payload(port as usize)   // msgh_local_port and payload are unión
    } else {
        trivfs_begin_using_protid(port)                    // msgh_request_port = msgh_local_port
    }
}

pub fn mig_bad_args(outp: *mut mig_reply_header_t) {
    unsafe { (*outp).RetCode = MIG_BAD_ARGUMENTS; }
}

//---------------------------------------------------------------------------//
// Handlers trivfs_S_io_* all ported to Rust (io_stubs.rs / io_handlers.rs    //
// / ioctl.rs). Only mig_deallocate remains a C extern.                       //
//---------------------------------------------------------------------------//

unsafe extern "C" {
    pub fn mig_deallocate(addr: vm_offset_t, size: vm_size_t);
}

//---------------------------------------------------------------------------//
// _Xio_get_conch ... _Xio_sigio, _Xio_revoke                                //
// Request = 24, Reply = mig_reply_header_t (32)                             //
//---------------------------------------------------------------------------//

pub unsafe extern "C-unwind" fn _Xio_get_conch(
    inp: *mut mach_msg_header_t,
    outp: *mut mig_reply_header_t,
) {
    if (*inp).msgh_size != size_of::<mach_msg_header_t>() as u32
        || (*inp).msgh_bits & MACH_MSGH_BITS_COMPLEX != 0 {
        mig_bad_args(outp);
        return;
    }
    let io_object = begin_using_io((*inp).msgh_bits, (*inp).msgh_local_port);
    let _guard = ProtidGuard::new(io_object);
    let reply = (*inp).msgh_remote_port;
    let reply_poly = mach_msgh_bits_remote((*inp).msgh_bits);
    (*outp).RetCode = trivfs_S_io_get_conch(io_object, reply, reply_poly);
}

pub unsafe extern "C-unwind" fn _Xio_release_conch(
    inp: *mut mach_msg_header_t,
    outp: *mut mig_reply_header_t,
) {
    if (*inp).msgh_size != size_of::<mach_msg_header_t>() as u32
        || (*inp).msgh_bits & MACH_MSGH_BITS_COMPLEX != 0 {
        mig_bad_args(outp);
        return;
    }
    let io_object = begin_using_io((*inp).msgh_bits, (*inp).msgh_local_port);
    let _guard = ProtidGuard::new(io_object);
    let reply = (*inp).msgh_remote_port;
    let reply_poly = mach_msgh_bits_remote((*inp).msgh_bits);
    (*outp).RetCode = trivfs_S_io_release_conch(io_object, reply, reply_poly);
}

pub unsafe extern "C-unwind" fn _Xio_eofnotify(
    inp: *mut mach_msg_header_t,
    outp: *mut mig_reply_header_t,
) {
    if (*inp).msgh_size != size_of::<mach_msg_header_t>() as u32
        || (*inp).msgh_bits & MACH_MSGH_BITS_COMPLEX != 0 {
        mig_bad_args(outp);
        return;
    }
    let io_object = begin_using_io((*inp).msgh_bits, (*inp).msgh_local_port);
    let _guard = ProtidGuard::new(io_object);
    let reply = (*inp).msgh_remote_port;
    let reply_poly = mach_msgh_bits_remote((*inp).msgh_bits);
    (*outp).RetCode = trivfs_S_io_eofnotify(io_object, reply, reply_poly);
}

pub unsafe extern "C-unwind" fn _Xio_readnotify(
    inp: *mut mach_msg_header_t,
    outp: *mut mig_reply_header_t,
) {
    if (*inp).msgh_size != size_of::<mach_msg_header_t>() as u32
        || (*inp).msgh_bits & MACH_MSGH_BITS_COMPLEX != 0 {
        mig_bad_args(outp);
        return;
    }
    let io_object = begin_using_io((*inp).msgh_bits, (*inp).msgh_local_port);
    let _guard = ProtidGuard::new(io_object);
    let reply = (*inp).msgh_remote_port;
    let reply_poly = mach_msgh_bits_remote((*inp).msgh_bits);
    (*outp).RetCode = trivfs_S_io_readnotify(io_object, reply, reply_poly);
}

pub unsafe extern "C-unwind" fn _Xio_readsleep(
    inp: *mut mach_msg_header_t,
    outp: *mut mig_reply_header_t,
) {
    if (*inp).msgh_size != size_of::<mach_msg_header_t>() as u32
        || (*inp).msgh_bits & MACH_MSGH_BITS_COMPLEX != 0 {
        mig_bad_args(outp);
        return;
    }
    let io_object = begin_using_io((*inp).msgh_bits, (*inp).msgh_local_port);
    let _guard = ProtidGuard::new(io_object);
    let reply = (*inp).msgh_remote_port;
    let reply_poly = mach_msgh_bits_remote((*inp).msgh_bits);
    (*outp).RetCode = trivfs_S_io_readsleep(io_object, reply, reply_poly);
}

pub unsafe extern "C-unwind" fn _Xio_sigio(
    inp: *mut mach_msg_header_t,
    outp: *mut mig_reply_header_t,
) {
    if (*inp).msgh_size != size_of::<mach_msg_header_t>() as u32
        || (*inp).msgh_bits & MACH_MSGH_BITS_COMPLEX != 0 {
        mig_bad_args(outp);
        return;
    }
    let io_object = begin_using_io((*inp).msgh_bits, (*inp).msgh_local_port);
    let _guard = ProtidGuard::new(io_object);
    let reply = (*inp).msgh_remote_port;
    let reply_poly = mach_msgh_bits_remote((*inp).msgh_bits);
    (*outp).RetCode = trivfs_S_io_sigio(io_object, reply, reply_poly);
}

// trivfs_S_io_revoke is already in Rust (io_handlers.rs:143)
pub unsafe extern "C-unwind" fn _Xio_revoke(
    inp: *mut mach_msg_header_t,
    outp: *mut mig_reply_header_t,
) {
    if (*inp).msgh_size != size_of::<mach_msg_header_t>() as u32
        || (*inp).msgh_bits & MACH_MSGH_BITS_COMPLEX != 0 {
        mig_bad_args(outp);
        return;
    }
    let io_object = begin_using_io((*inp).msgh_bits, (*inp).msgh_local_port);
    let _guard = ProtidGuard::new(io_object);
    let reply = (*inp).msgh_remote_port;
    let reply_poly = mach_msgh_bits_remote((*inp).msgh_bits);
    (*outp).RetCode = trivfs_S_io_revoke(io_object, reply, reply_poly);
}

//---------------------------------------------------------------------------//
// _Xio_set_all_openmodes ... _Xio_mod_owner  (Request = 32)                 //
//---------------------------------------------------------------------------//

#[repr(C)]
struct Req_set_all_openmodes {
    Head: mach_msg_header_t,
    newbitsType: mach_msg_type_t,
    newbits: c_int,
}

pub unsafe extern "C-unwind" fn _Xio_set_all_openmodes(
    inp: *mut mach_msg_header_t,
    outp: *mut mig_reply_header_t,
) {
    let inp = inp as *const Req_set_all_openmodes;
    if (*inp).Head.msgh_size != size_of::<Req_set_all_openmodes>() as u32 || (*inp).Head.msgh_bits & MACH_MSGH_BITS_COMPLEX != 0 {
        mig_bad_args(outp);
        return;
    }
    if (*inp).newbitsType != T_INTEGER_32_1 {
        mig_bad_args(outp);
        return;
    }
    let io_object = begin_using_io((*inp).Head.msgh_bits, (*inp).Head.msgh_local_port);
    let _guard = ProtidGuard::new(io_object);
    let reply = (*inp).Head.msgh_remote_port;
    let reply_poly = mach_msgh_bits_remote((*inp).Head.msgh_bits);
    (*outp).RetCode = trivfs_S_io_set_all_openmodes(io_object, reply, reply_poly, (*inp).newbits);
}

#[repr(C)]
struct Req_set_some_openmodes {
    Head: mach_msg_header_t,
    bitsType: mach_msg_type_t,
    bits: c_int,
}

pub unsafe extern "C-unwind" fn _Xio_set_some_openmodes(
    inp: *mut mach_msg_header_t,
    outp: *mut mig_reply_header_t,
) {
    let inp = inp as *const Req_set_some_openmodes;
    if (*inp).Head.msgh_size != size_of::<Req_set_some_openmodes>() as u32 
        || (*inp).Head.msgh_bits & MACH_MSGH_BITS_COMPLEX != 0 {
        mig_bad_args(outp);
        return;
    }
    if (*inp).bitsType != T_INTEGER_32_1 {
        mig_bad_args(outp);
        return;
    }
    let io_object = begin_using_io((*inp).Head.msgh_bits, (*inp).Head.msgh_local_port);
    let _guard = ProtidGuard::new(io_object);
    let reply = (*inp).Head.msgh_remote_port;
    let reply_poly = mach_msgh_bits_remote((*inp).Head.msgh_bits);
    (*outp).RetCode = trivfs_S_io_set_some_openmodes(io_object, reply, reply_poly, (*inp).bits);
}

#[repr(C)]
struct Req_clear_some_openmodes {
    Head: mach_msg_header_t,
    bitsType: mach_msg_type_t,
    bits: c_int,
}

pub unsafe extern "C-unwind" fn _Xio_clear_some_openmodes(
    inp: *mut mach_msg_header_t,
    outp: *mut mig_reply_header_t,
) {
    let inp = inp as *const Req_clear_some_openmodes;
    if (*inp).Head.msgh_size != size_of::<Req_clear_some_openmodes>() as u32 
        || (*inp).Head.msgh_bits & MACH_MSGH_BITS_COMPLEX != 0 {
        mig_bad_args(outp);
        return;
    }
    if (*inp).bitsType != T_INTEGER_32_1 {
        mig_bad_args(outp);
        return;
    }
    let io_object = begin_using_io((*inp).Head.msgh_bits, (*inp).Head.msgh_local_port);
    let _guard = ProtidGuard::new(io_object);
    let reply = (*inp).Head.msgh_remote_port;
    let reply_poly = mach_msgh_bits_remote((*inp).Head.msgh_bits);
    (*outp).RetCode = trivfs_S_io_clear_some_openmodes(io_object, reply, reply_poly, (*inp).bits);
}

#[repr(C)]
struct Req_mod_owner {
    Head: mach_msg_header_t,
    ownerType: mach_msg_type_t,
    owner: c_int,
}

pub unsafe extern "C-unwind" fn _Xio_mod_owner(
    inp: *mut mach_msg_header_t,
    outp: *mut mig_reply_header_t,
) {
    let inp = inp as *const Req_mod_owner;
    if (*inp).Head.msgh_size != size_of::<Req_mod_owner>() as u32 
        || (*inp).Head.msgh_bits & MACH_MSGH_BITS_COMPLEX != 0 {
        mig_bad_args(outp);
        return;
    }
    if (*inp).ownerType != T_INTEGER_32_1 {
        mig_bad_args(outp);
        return;
    }
    let io_object = begin_using_io((*inp).Head.msgh_bits, (*inp).Head.msgh_local_port);
    let _guard = ProtidGuard::new(io_object);
    let reply = (*inp).Head.msgh_remote_port;
    let reply_poly = mach_msgh_bits_remote((*inp).Head.msgh_bits);
    (*outp).RetCode = trivfs_S_io_mod_owner(io_object, reply, reply_poly, (*inp).owner);
}

//---------------------------------------------------------------------------//
// _Xio_readable, _Xio_get_openmodes, _Xio_get_owner  (Reply = 40)           //
//---------------------------------------------------------------------------//

#[repr(C)]
struct Reply_io_readable {
    Head: mach_msg_header_t,
    RetCodeType: mach_msg_type_t,
    RetCode: kern_return_t,
    amountType: mach_msg_type_t,
    amount: vm_size_t,
}

pub unsafe extern "C-unwind" fn _Xio_readable(
    inp: *mut mach_msg_header_t,
    outp: *mut Reply_io_readable,
) {
    if (*inp).msgh_size != size_of::<mach_msg_header_t>() as u32
        || (*inp).msgh_bits & MACH_MSGH_BITS_COMPLEX != 0 {
        mig_bad_args(outp as *mut mig_reply_header_t);
        return;
    }
    let io_object = begin_using_io((*inp).msgh_bits, (*inp).msgh_local_port);
    let _guard = ProtidGuard::new(io_object);
    let reply = (*inp).msgh_remote_port;
    let reply_poly = mach_msgh_bits_remote((*inp).msgh_bits);
    (*outp).RetCode = trivfs_S_io_readable(io_object, reply, reply_poly, &mut (*outp).amount as *mut vm_size_t as *mut mach_msg_type_number_t);
    if (*outp).RetCode != KERN_SUCCESS {
        return;
    }
    (*outp).Head.msgh_size = size_of::<Reply_io_readable>() as u32;
    (*outp).amountType = T_VM_OFFSET_1;
}

#[repr(C)]
struct Reply_io_get_openmodes {
    Head: mach_msg_header_t,
    RetCodeType: mach_msg_type_t,
    RetCode: kern_return_t,
    bitsType: mach_msg_type_t,
    bits: c_int,
}

pub unsafe extern "C-unwind" fn _Xio_get_openmodes(
    inp: *mut mach_msg_header_t,
    outp: *mut Reply_io_get_openmodes,
) {
    if (*inp).msgh_size != size_of::<mach_msg_header_t>() as u32
        || (*inp).msgh_bits & MACH_MSGH_BITS_COMPLEX != 0 {
        mig_bad_args(outp as *mut mig_reply_header_t);
        return;
    }
    let io_object = begin_using_io((*inp).msgh_bits, (*inp).msgh_local_port);
    let _guard = ProtidGuard::new(io_object);
    let reply = (*inp).msgh_remote_port;
    let reply_poly = mach_msgh_bits_remote((*inp).msgh_bits);
    (*outp).RetCode = trivfs_S_io_get_openmodes(io_object, reply, reply_poly, &mut (*outp).bits);
    if (*outp).RetCode != KERN_SUCCESS {
        return;
    }
    (*outp).Head.msgh_size = size_of::<Reply_io_get_openmodes>() as u32;
    (*outp).bitsType = T_INTEGER_32_1;
}

#[repr(C)]
struct Reply_io_get_owner {
    Head: mach_msg_header_t,
    RetCodeType: mach_msg_type_t,
    RetCode: kern_return_t,
    ownerType: mach_msg_type_t,
    owner: c_int,
}

pub unsafe extern "C-unwind" fn _Xio_get_owner(
    inp: *mut mach_msg_header_t,
    outp: *mut Reply_io_get_owner,
) {
    if (*inp).msgh_size != size_of::<mach_msg_header_t>() as u32
        || (*inp).msgh_bits & MACH_MSGH_BITS_COMPLEX != 0 {
        mig_bad_args(outp as *mut mig_reply_header_t);
        return;
    }
    let io_object = begin_using_io((*inp).msgh_bits, (*inp).msgh_local_port);
    let _guard = ProtidGuard::new(io_object);
    let reply = (*inp).msgh_remote_port;
    let reply_poly = mach_msgh_bits_remote((*inp).msgh_bits);
    (*outp).RetCode = trivfs_S_io_get_owner(io_object, reply, reply_poly, &mut (*outp).owner);
    if (*outp).RetCode != KERN_SUCCESS {
        return;
    }
    (*outp).Head.msgh_size = size_of::<Reply_io_get_owner>() as u32;
    (*outp).ownerType = T_INTEGER_32_1;
}

//---------------------------------------------------------------------------//
// _Xio_select, _Xio_seek, _Xio_select_timeout, _Xio_pathconf,               //
// _Xio_prenotify, _Xio_postnotify                                           //
//---------------------------------------------------------------------------//

#[repr(C)]
struct Req_select {
    Head: mach_msg_header_t,
    select_typeType: mach_msg_type_t,
    select_type: c_int,
}

#[repr(C)]
struct Reply_select {
    Head: mach_msg_header_t,
    RetCodeType: mach_msg_type_t,
    RetCode: kern_return_t,
    select_typeType: mach_msg_type_t,
    select_type: c_int,
}

pub unsafe extern "C-unwind" fn _Xio_select(
    inp: *mut mach_msg_header_t,
    outp: *mut Reply_select,
) {
    let inp = inp as *mut Req_select;
    if (*inp).Head.msgh_size != size_of::<Req_select>() as u32
        || (*inp).Head.msgh_bits & MACH_MSGH_BITS_COMPLEX != 0
    {
        mig_bad_args(outp as *mut mig_reply_header_t);
        return;
    }
    if (*inp).select_typeType != T_INTEGER_32_1 {
        mig_bad_args(outp as *mut mig_reply_header_t);
        return;
    }
    let io_object = begin_using_io((*inp).Head.msgh_bits, (*inp).Head.msgh_local_port);
    let _guard = ProtidGuard::new(io_object);
    let reply = (*inp).Head.msgh_remote_port;
    let reply_poly = mach_msgh_bits_remote((*inp).Head.msgh_bits);
    (*outp).RetCode = trivfs_S_io_select(io_object, reply, reply_poly, &mut (*inp).select_type);
    if (*outp).RetCode != KERN_SUCCESS { return; }
    (*outp).Head.msgh_size = size_of::<Reply_select>() as u32;
    (*outp).select_typeType = T_INTEGER_32_1;
    (*outp).select_type = (*inp).select_type;
}

#[repr(C)]
struct Req_seek {
    Head: mach_msg_header_t,
    offsetType: mach_msg_type_t,
    offset: loff_t,
    whenceType: mach_msg_type_t,
    whence: c_int,
}

#[repr(C)]
struct Reply_seek {
    Head: mach_msg_header_t,
    RetCodeType: mach_msg_type_t,
    RetCode: kern_return_t,
    newpType: mach_msg_type_t,
    newp: loff_t,
}

pub unsafe extern "C-unwind" fn _Xio_seek(
    inp: *mut mach_msg_header_t,
    outp: *mut Reply_seek,
) {
    let inp = inp as *const Req_seek;
    if (*inp).Head.msgh_size != size_of::<Req_seek>() as u32
        || (*inp).Head.msgh_bits & MACH_MSGH_BITS_COMPLEX != 0
    {
        mig_bad_args(outp as *mut mig_reply_header_t);
        return;
    }
    if (*inp).offsetType != T_INTEGER_64_1 || (*inp).whenceType != T_INTEGER_32_1 {
        mig_bad_args(outp as *mut mig_reply_header_t);
        return;
    }
    let io_object = begin_using_io((*inp).Head.msgh_bits, (*inp).Head.msgh_local_port);
    let _guard = ProtidGuard::new(io_object);
    let reply = (*inp).Head.msgh_remote_port;
    let reply_poly = mach_msgh_bits_remote((*inp).Head.msgh_bits);
    (*outp).RetCode =
        trivfs_S_io_seek(io_object, reply, reply_poly, (*inp).offset, (*inp).whence, &mut (*outp).newp);
    if (*outp).RetCode != KERN_SUCCESS { return; }
    (*outp).Head.msgh_size = size_of::<Reply_seek>() as u32;
    (*outp).newpType = T_INTEGER_64_1;
}

#[repr(C)]
struct Req_select_timeout {
    Head: mach_msg_header_t,
    timeoutType: mach_msg_type_t,
    #[cfg(target_pointer_width = "32")]
    timeout: [c_int; 2],                 // timespec_t {long,long}
    #[cfg(target_pointer_width = "64")]
    timeout: [i64; 2],
    select_typeType: mach_msg_type_t,
    select_type: c_int,
}

pub unsafe extern "C-unwind" fn _Xio_select_timeout(
    inp: *mut mach_msg_header_t,
    outp: *mut Reply_select,
) {
    let inp = inp as *mut Req_select_timeout;
    if (*inp).Head.msgh_size != size_of::<Req_select_timeout>() as u32
        || (*inp).Head.msgh_bits & MACH_MSGH_BITS_COMPLEX != 0
    {
        mig_bad_args(outp as *mut mig_reply_header_t);
        return;
    }
    if (*inp).timeoutType != T_TIMESPEC || (*inp).select_typeType != T_INTEGER_32_1 {
        mig_bad_args(outp as *mut mig_reply_header_t);
        return;
    }
    let io_object = begin_using_io((*inp).Head.msgh_bits, (*inp).Head.msgh_local_port);
    let _guard = ProtidGuard::new(io_object);
    let reply = (*inp).Head.msgh_remote_port;
    let reply_poly = mach_msgh_bits_remote((*inp).Head.msgh_bits);
    (*outp).RetCode = trivfs_S_io_select_timeout(
        io_object, reply, reply_poly,
        (*inp).timeout.as_mut_ptr() as *mut u8,
        &mut (*inp).select_type,
    );
    if (*outp).RetCode != KERN_SUCCESS { return; }
    (*outp).Head.msgh_size = size_of::<Reply_select>() as u32;
    (*outp).select_typeType = T_INTEGER_32_1;
    (*outp).select_type = (*inp).select_type;
}

#[repr(C)]
struct Req_pathconf {
    Head: mach_msg_header_t,
    nameType: mach_msg_type_t,
    name: c_int,
}

#[repr(C)]
struct Reply_pathconf {
    Head: mach_msg_header_t,
    RetCodeType: mach_msg_type_t,
    RetCode: kern_return_t,
    valueType: mach_msg_type_t,
    value: c_int,
}

pub unsafe extern "C-unwind" fn _Xio_pathconf(
    inp: *mut mach_msg_header_t,
    outp: *mut Reply_pathconf,
) {
    let inp = inp as *const Req_pathconf;
    if (*inp).Head.msgh_size != size_of::<Req_pathconf>() as u32
        || (*inp).Head.msgh_bits & MACH_MSGH_BITS_COMPLEX != 0
    {
        mig_bad_args(outp as *mut mig_reply_header_t);
        return;
    }
    if (*inp).nameType != T_INTEGER_32_1 {
        mig_bad_args(outp as *mut mig_reply_header_t);
        return;
    }
    let io_object = begin_using_io((*inp).Head.msgh_bits, (*inp).Head.msgh_local_port);
    let _guard = ProtidGuard::new(io_object);
    let reply = (*inp).Head.msgh_remote_port;
    let reply_poly = mach_msgh_bits_remote((*inp).Head.msgh_bits);
    (*outp).RetCode = trivfs_S_io_pathconf(io_object, reply, reply_poly, (*inp).name, &mut (*outp).value);
    if (*outp).RetCode != KERN_SUCCESS { return; }
    (*outp).Head.msgh_size = size_of::<Reply_pathconf>() as u32;
    (*outp).valueType = T_INTEGER_32_1;
}

#[repr(C)]
struct Req_prenotify {
    Head: mach_msg_header_t,
    write_startType: mach_msg_type_t,
    write_start: vm_offset_t,
    write_endType: mach_msg_type_t,
    write_end: vm_offset_t,
}

pub unsafe extern "C-unwind" fn _Xio_prenotify(
    inp: *mut mach_msg_header_t,
    outp: *mut mig_reply_header_t,
) {
    let inp = inp as *const Req_prenotify;
    if (*inp).Head.msgh_size != size_of::<Req_prenotify>() as u32
        || (*inp).Head.msgh_bits & MACH_MSGH_BITS_COMPLEX != 0
    {
        mig_bad_args(outp);
        return;
    }
    if (*inp).write_startType != T_VM_OFFSET_1 || (*inp).write_endType != T_VM_OFFSET_1 {
        mig_bad_args(outp);
        return;
    }
    let io_object = begin_using_io((*inp).Head.msgh_bits, (*inp).Head.msgh_local_port);
    let _guard = ProtidGuard::new(io_object);
    let reply = (*inp).Head.msgh_remote_port;
    let reply_poly = mach_msgh_bits_remote((*inp).Head.msgh_bits);
    (*outp).RetCode = trivfs_S_io_prenotify(io_object, reply, reply_poly, (*inp).write_start, (*inp).write_end);
}

pub unsafe extern "C-unwind" fn _Xio_postnotify(
    inp: *mut mach_msg_header_t,
    outp: *mut mig_reply_header_t,
) {
    let inp = inp as *const Req_prenotify;
    if (*inp).Head.msgh_size != size_of::<Req_prenotify>() as u32
        || (*inp).Head.msgh_bits & MACH_MSGH_BITS_COMPLEX != 0
    {
        mig_bad_args(outp);
        return;
    }
    if (*inp).write_startType != T_VM_OFFSET_1 || (*inp).write_endType != T_VM_OFFSET_1 {
        mig_bad_args(outp);
        return;
    }
    let io_object = begin_using_io((*inp).Head.msgh_bits, (*inp).Head.msgh_local_port);
    let _guard = ProtidGuard::new(io_object);
    let reply = (*inp).Head.msgh_remote_port;
    let reply_poly = mach_msgh_bits_remote((*inp).Head.msgh_bits);
    (*outp).RetCode = trivfs_S_io_postnotify(io_object, reply, reply_poly, (*inp).write_start, (*inp).write_end);
}

//---------------------------------------------------------------------------//
// _Xio_get_icky_async_id, _Xio_duplicate, _Xio_map_cntl, _Xio_map           //
// Request = 24; Reply with polymorphic port (conditional COMPLEX)          //
//---------------------------------------------------------------------------//

#[repr(C)]
struct Reply_icky_async_id {
    Head: mach_msg_header_t,
    RetCodeType: mach_msg_type_t,
    RetCode: kern_return_t,
    icky_async_id_portType: mach_msg_type_t,
    icky_async_id_port: mach_port_t,
}

pub unsafe extern "C-unwind" fn _Xio_get_icky_async_id(
    inp: *mut mach_msg_header_t,
    outp: *mut Reply_icky_async_id,
) {
    if (*inp).msgh_size != size_of::<mach_msg_header_t>() as u32
        || (*inp).msgh_bits & MACH_MSGH_BITS_COMPLEX != 0 {
        mig_bad_args(outp as *mut mig_reply_header_t);
        return;
    }
    let io_object = begin_using_io((*inp).msgh_bits, (*inp).msgh_local_port);
    let _guard = ProtidGuard::new(io_object);
    let reply = (*inp).msgh_remote_port;
    let reply_poly = mach_msgh_bits_remote((*inp).msgh_bits);
    let mut icky_async_id_portPoly: mach_msg_type_name_t = 0;
    (*outp).RetCode = trivfs_S_io_get_icky_async_id(
        io_object, reply, reply_poly,
        &mut (*outp).icky_async_id_port, &mut icky_async_id_portPoly,
    );
    if (*outp).RetCode != KERN_SUCCESS { return; }
    (*outp).Head.msgh_size = size_of::<Reply_icky_async_id>() as u32;
    let mut msgh_simple = true;
    (*outp).icky_async_id_portType = type_desc(icky_async_id_portPoly, MACH_PORT_INLINE_MSGT_SIZE, 1);
    if mach_msg_type_port_any_right(icky_async_id_portPoly) { msgh_simple = false; }
    if !msgh_simple { (*outp).Head.msgh_bits |= MACH_MSGH_BITS_COMPLEX; }
}

#[repr(C)]
struct Reply_duplicate {
    Head: mach_msg_header_t,
    RetCodeType: mach_msg_type_t,
    RetCode: kern_return_t,
    newportType: mach_msg_type_t,
    newport: mach_port_t,
}

pub unsafe extern "C-unwind" fn _Xio_duplicate(
    inp: *mut mach_msg_header_t,
    outp: *mut Reply_duplicate,
) {
    if (*inp).msgh_size != size_of::<mach_msg_header_t>() as u32
        || (*inp).msgh_bits & MACH_MSGH_BITS_COMPLEX != 0 {
        mig_bad_args(outp as *mut mig_reply_header_t);
        return;
    }
    let io_object = begin_using_io((*inp).msgh_bits, (*inp).msgh_local_port);
    let _guard = ProtidGuard::new(io_object);
    let reply = (*inp).msgh_remote_port;
    let reply_poly = mach_msgh_bits_remote((*inp).msgh_bits);
    let mut newportPoly: mach_msg_type_name_t = 0;
    (*outp).RetCode = trivfs_S_io_duplicate(
        io_object, reply, reply_poly,
        &mut (*outp).newport, &mut newportPoly,
    );
    if (*outp).RetCode != KERN_SUCCESS { return; }
    (*outp).Head.msgh_size = size_of::<Reply_duplicate>() as u32;
    let mut msgh_simple = true;
    (*outp).newportType = type_desc(newportPoly, MACH_PORT_INLINE_MSGT_SIZE, 1);
    if mach_msg_type_port_any_right(newportPoly) { msgh_simple = false; }
    if !msgh_simple { (*outp).Head.msgh_bits |= MACH_MSGH_BITS_COMPLEX; }
}

#[repr(C)]
struct Reply_map_cntl {
    Head: mach_msg_header_t,
    RetCodeType: mach_msg_type_t,
    RetCode: kern_return_t,
    memobjType: mach_msg_type_t,
    memobj: mach_port_t,
}

pub unsafe extern "C-unwind" fn _Xio_map_cntl(
    inp: *mut mach_msg_header_t,
    outp: *mut Reply_map_cntl,
) {
    if (*inp).msgh_size != size_of::<mach_msg_header_t>() as u32
        || (*inp).msgh_bits & MACH_MSGH_BITS_COMPLEX != 0 {
        mig_bad_args(outp as *mut mig_reply_header_t);
        return;
    }
    let io_object = begin_using_io((*inp).msgh_bits, (*inp).msgh_local_port);
    let _guard = ProtidGuard::new(io_object);
    let reply = (*inp).msgh_remote_port;
    let reply_poly = mach_msgh_bits_remote((*inp).msgh_bits);
    let mut memobjPoly: mach_msg_type_name_t = 0;
    (*outp).RetCode = trivfs_S_io_map_cntl(
        io_object, reply, reply_poly,
        &mut (*outp).memobj, &mut memobjPoly,
    );
    if (*outp).RetCode != KERN_SUCCESS { return; }
    (*outp).Head.msgh_size = size_of::<Reply_map_cntl>() as u32;
    let mut msgh_simple = true;
    (*outp).memobjType = type_desc(memobjPoly, MACH_PORT_INLINE_MSGT_SIZE, 1);
    if mach_msg_type_port_any_right(memobjPoly) { msgh_simple = false; }
    if !msgh_simple { (*outp).Head.msgh_bits |= MACH_MSGH_BITS_COMPLEX; }
}

#[repr(C)]
struct Reply_map {
    Head: mach_msg_header_t,
    RetCodeType: mach_msg_type_t,
    RetCode: kern_return_t,
    memobjrdType: mach_msg_type_t,
    memobjrd: mach_port_t,
    memobjwtType: mach_msg_type_t,
    memobjwt: mach_port_t,
}

pub unsafe extern "C-unwind" fn _Xio_map(
    inp: *mut mach_msg_header_t,
    outp: *mut Reply_map,
) {
    if (*inp).msgh_size != size_of::<mach_msg_header_t>() as u32
        || (*inp).msgh_bits & MACH_MSGH_BITS_COMPLEX != 0 {
        mig_bad_args(outp as *mut mig_reply_header_t);
        return;
    }
    let io_object = begin_using_io((*inp).msgh_bits, (*inp).msgh_local_port);
    let _guard = ProtidGuard::new(io_object);
    let reply = (*inp).msgh_remote_port;
    let reply_poly = mach_msgh_bits_remote((*inp).msgh_bits);
    let mut memobjrdPoly: mach_msg_type_name_t = 0;
    let mut memobjwtPoly: mach_msg_type_name_t = 0;
    (*outp).RetCode = trivfs_S_io_map(
        io_object, reply, reply_poly,
        &mut (*outp).memobjrd, &mut memobjrdPoly,
        &mut (*outp).memobjwt, &mut memobjwtPoly,
    );
    if (*outp).RetCode != KERN_SUCCESS { return; }
    (*outp).Head.msgh_size = size_of::<Reply_map>() as u32;
    let mut msgh_simple = true;
    (*outp).memobjrdType = type_desc(memobjrdPoly, MACH_PORT_INLINE_MSGT_SIZE, 1);
    if mach_msg_type_port_any_right(memobjrdPoly) { msgh_simple = false; }
    (*outp).memobjwtType = type_desc(memobjwtPoly, MACH_PORT_INLINE_MSGT_SIZE, 1);
    if mach_msg_type_port_any_right(memobjwtPoly) { msgh_simple = false; }
    if !msgh_simple { (*outp).Head.msgh_bits |= MACH_MSGH_BITS_COMPLEX; }
}

//---------------------------------------------------------------------------//
// _Xio_identity, _Xio_stat, _Xio_server_version                             //
//---------------------------------------------------------------------------//

#[repr(C)]
struct Reply_identity {
    Head: mach_msg_header_t,
    RetCodeType: mach_msg_type_t,
    RetCode: kern_return_t,
    idportType: mach_msg_type_t,
    idport: mach_port_t,
    fsidportType: mach_msg_type_t,
    fsidport: mach_port_t,
    filenoType: mach_msg_type_t,
    fileno: u64,
}

pub unsafe extern "C-unwind" fn _Xio_identity(
    inp: *mut mach_msg_header_t,
    outp: *mut Reply_identity,
) {
    if (*inp).msgh_size != size_of::<mach_msg_header_t>() as u32
        || (*inp).msgh_bits & MACH_MSGH_BITS_COMPLEX != 0 {
        mig_bad_args(outp as *mut mig_reply_header_t);
        return;
    }
    let io_object = begin_using_io((*inp).msgh_bits, (*inp).msgh_local_port);
    let _guard = ProtidGuard::new(io_object);
    let reply = (*inp).msgh_remote_port;
    let reply_poly = mach_msgh_bits_remote((*inp).msgh_bits);
    let mut idportPoly: mach_msg_type_name_t = 0;
    let mut fsidportPoly: mach_msg_type_name_t = 0;
    (*outp).RetCode = trivfs_S_io_identity(
        io_object, reply, reply_poly,
        &mut (*outp).idport, &mut idportPoly,
        &mut (*outp).fsidport, &mut fsidportPoly,
        &mut (*outp).fileno,
    );
    if (*outp).RetCode != KERN_SUCCESS { return; }
    (*outp).Head.msgh_size = size_of::<Reply_identity>() as u32;
    let mut msgh_simple = true;
    (*outp).idportType = type_desc(idportPoly, MACH_PORT_INLINE_MSGT_SIZE, 1);
    if mach_msg_type_port_any_right(idportPoly) { msgh_simple = false; }
    (*outp).fsidportType = type_desc(fsidportPoly, MACH_PORT_INLINE_MSGT_SIZE, 1);
    if mach_msg_type_port_any_right(fsidportPoly) { msgh_simple = false; }
    (*outp).filenoType = T_INTEGER_64_1;
    if !msgh_simple { (*outp).Head.msgh_bits |= MACH_MSGH_BITS_COMPLEX; }
}

#[repr(C)]
struct Reply_stat {
    Head: mach_msg_header_t,
    RetCodeType: mach_msg_type_t,
    RetCode: kern_return_t,
    stat_infoType: mach_msg_type_t,
    stat_info: io_statbuf_t,
}

pub unsafe extern "C-unwind" fn _Xio_stat(
    inp: *mut mach_msg_header_t,
    outp: *mut Reply_stat,
) {
    if (*inp).msgh_size != size_of::<mach_msg_header_t>() as u32
        || (*inp).msgh_bits & MACH_MSGH_BITS_COMPLEX != 0 {
        mig_bad_args(outp as *mut mig_reply_header_t);
        return;
    }
    let io_object = begin_using_io((*inp).msgh_bits, (*inp).msgh_local_port);
    let _guard = ProtidGuard::new(io_object);
    let reply = (*inp).msgh_remote_port;
    let reply_poly = mach_msgh_bits_remote((*inp).msgh_bits);
    (*outp).RetCode = trivfs_S_io_stat(io_object, reply, reply_poly, &mut (*outp).stat_info);
    if (*outp).RetCode != KERN_SUCCESS { return; }
    (*outp).Head.msgh_size = size_of::<Reply_stat>() as u32;
    (*outp).stat_infoType = type_desc(MACH_MSG_TYPE_INTEGER_32, 32, 32);
}

#[repr(C)]
struct Reply_server_version {
    Head: mach_msg_header_t,
    RetCodeType: mach_msg_type_t,
    RetCode: kern_return_t,
    server_nameType: mach_msg_type_t,
    server_name: [c_char; 1024],
    server_major_versionType: mach_msg_type_t,
    server_major_version: c_int,
    server_minor_versionType: mach_msg_type_t,
    server_minor_version: c_int,
    server_edit_levelType: mach_msg_type_t,
    server_edit_level: c_int,
}

pub unsafe extern "C-unwind" fn _Xio_server_version(
    inp: *mut mach_msg_header_t,
    outp: *mut Reply_server_version,
) {
    if (*inp).msgh_size != size_of::<mach_msg_header_t>() as u32
        || (*inp).msgh_bits & MACH_MSGH_BITS_COMPLEX != 0 {
        mig_bad_args(outp as *mut mig_reply_header_t);
        return;
    }
    let io_object = begin_using_io((*inp).msgh_bits, (*inp).msgh_local_port);
    let _guard = ProtidGuard::new(io_object);
    let reply = (*inp).msgh_remote_port;
    let reply_poly = mach_msgh_bits_remote((*inp).msgh_bits);
    (*outp).RetCode = trivfs_S_io_server_version(
        io_object, reply, reply_poly,
        (*outp).server_name.as_mut_ptr(),
        &mut (*outp).server_major_version,
        &mut (*outp).server_minor_version,
        &mut (*outp).server_edit_level,
    );
    if (*outp).RetCode != KERN_SUCCESS { return; }
    (*outp).Head.msgh_size = size_of::<Reply_server_version>() as u32;
    (*outp).server_nameType = T_STRING_C_1024;
    (*outp).server_major_versionType = T_INTEGER_32_1;
    (*outp).server_minor_versionType = T_INTEGER_32_1;
    (*outp).server_edit_levelType = T_INTEGER_32_1;
}

//---------------------------------------------------------------------------//
// _Xio_async, _Xio_reauthenticate  (Request COMPLEX: port entrante)         //
//---------------------------------------------------------------------------//

#[repr(C)]
struct Req_async {
    Head: mach_msg_header_t,
    notify_portType: mach_msg_type_t,
    notify_port: mach_port_t,
}

#[repr(C)]
struct Reply_async {
    Head: mach_msg_header_t,
    RetCodeType: mach_msg_type_t,
    RetCode: kern_return_t,
    async_id_portType: mach_msg_type_t,
    async_id_port: mach_port_t,
}

pub unsafe extern "C-unwind" fn _Xio_async(
    inp: *mut mach_msg_header_t,
    outp: *mut Reply_async,
) {
    let inp = inp as *mut Req_async;
    /*eprintln!("[dbg] _Xio_async size={} size_Req={} bits={:#010x} complex={} type={:#010x} expect={:#010x}",
    (*inp).Head.msgh_size, size_of::<Req_async>(),
    (*inp).Head.msgh_bits, (*inp).Head.msgh_bits & MACH_MSGH_BITS_COMPLEX,
    (*inp).notify_portType, T_PORT_SEND_1);*/
    if (*inp).Head.msgh_size != size_of::<Req_async>() as u32
        || (*inp).Head.msgh_bits & MACH_MSGH_BITS_COMPLEX == 0
    {
        mig_bad_args(outp as *mut mig_reply_header_t);
        return;
    }
    if (*inp).notify_portType != T_PORT_SEND_1 {
        mig_bad_args(outp as *mut mig_reply_header_t);
        return;
    }
    let io_object = begin_using_io((*inp).Head.msgh_bits, (*inp).Head.msgh_local_port);
    let _guard = ProtidGuard::new(io_object);
    let reply = (*inp).Head.msgh_remote_port;
    let reply_poly = mach_msgh_bits_remote((*inp).Head.msgh_bits);
    let mut async_id_portPoly: mach_msg_type_name_t = 0;
    (*outp).RetCode = trivfs_S_io_async(
        io_object, reply, reply_poly,
        (*inp).notify_port,
        &mut (*outp).async_id_port, &mut async_id_portPoly,
    );
    if (*outp).RetCode != KERN_SUCCESS { return; }
    (*outp).Head.msgh_size = size_of::<Reply_async>() as u32;
    let mut msgh_simple = true;
    (*outp).async_id_portType = type_desc(async_id_portPoly, MACH_PORT_INLINE_MSGT_SIZE, 1);
    if mach_msg_type_port_any_right(async_id_portPoly) { msgh_simple = false; }
    if !msgh_simple { (*outp).Head.msgh_bits |= MACH_MSGH_BITS_COMPLEX; }
}

#[repr(C)]
struct Req_reauthenticate {
    Head: mach_msg_header_t,
    rendezvous2Type: mach_msg_type_t,
    rendezvous2: mach_port_t,
}

pub unsafe extern "C-unwind" fn _Xio_reauthenticate(
    inp: *mut mach_msg_header_t,
    outp: *mut mig_reply_header_t,
) {
    let inp = inp as *const Req_reauthenticate;
    if (*inp).Head.msgh_size != size_of::<Req_reauthenticate>() as u32
        || (*inp).Head.msgh_bits & MACH_MSGH_BITS_COMPLEX == 0
    {
        mig_bad_args(outp);
        return;
    }
    if (*inp).rendezvous2Type != T_PORT_SEND_1 {
        mig_bad_args(outp);
        return;
    }
    let io_object = begin_using_io((*inp).Head.msgh_bits, (*inp).Head.msgh_local_port);
    let _guard = ProtidGuard::new(io_object);
    let reply = (*inp).Head.msgh_remote_port;
    let reply_poly = mach_msgh_bits_remote((*inp).Head.msgh_bits);
    (*outp).RetCode = trivfs_S_io_reauthenticate(io_object, reply, reply_poly, (*inp).rendezvous2);
}

#[repr(C)]
union WriteData { inline: [u8; 2048], ool: *const c_char }

#[repr(C)]
struct Req_write {
    Head: mach_msg_header_t,
    dataType: mach_msg_type_long_t,
    data: WriteData,
    offsetType: mach_msg_type_t,
    offset: loff_t,
}

#[repr(C)]
struct Reply_write {
    Head: mach_msg_header_t,
    RetCodeType: mach_msg_type_t,
    RetCode: kern_return_t,
    amountType: mach_msg_type_t,
    amount: vm_size_t,
}

pub unsafe extern "C-unwind" fn _Xio_write(inp: *mut mach_msg_header_t, outp: *mut Reply_write) {
    let inp = inp as *const Req_write;
    let base = size_of::<mach_msg_header_t>() + size_of::<mach_msg_type_long_t>()
        + size_of::<mach_msg_type_t>() + size_of::<loff_t>();          // 48 ambas arquit.
    let msgh_size = (*inp).Head.msgh_size;
    if msgh_size < base as u32 { mig_bad_args(outp as *mut mig_reply_header_t); return; }
    if !(*inp).dataType.is_longform() || (*inp).dataType.name() != MACH_MSG_TYPE_CHAR as u16
        || (*inp).dataType.size() != 8
    { mig_bad_args(outp as *mut mig_reply_header_t); return; }
    let delta = if (*inp).dataType.is_inline() {
        // mach_msg_align in u64: avoids the usize wrap on 32 bits for a
        // huge msgtl_number (0xFFFFFFFF → delta=0).
        ((*inp).dataType.number() as u64 + 3) & !3
    } else { size_of::<*const c_char>() as u64 };
    let total = base as u64 + delta;
    if msgh_size as u64 != total || delta > isize::MAX as u64 {
        mig_bad_args(outp as *mut mig_reply_header_t); return;
    }
    let tail_off = size_of::<mach_msg_header_t>() + size_of::<mach_msg_type_long_t>();
    let tail = (inp as *const u8).add(tail_off + delta as usize);
    let offset_type = *(tail as *const mach_msg_type_t);
    let offset = *(tail.add(size_of::<mach_msg_type_t>()) as *const loff_t);
    if offset_type != T_INTEGER_64_1 { mig_bad_args(outp as *mut mig_reply_header_t); return; }

    let io_object = begin_using_io((*inp).Head.msgh_bits, (*inp).Head.msgh_local_port);
    let _guard = ProtidGuard::new(io_object);
    let reply = (*inp).Head.msgh_remote_port;
    let reply_poly = mach_msgh_bits_remote((*inp).Head.msgh_bits);
    let (data_ptr, inline) = if (*inp).dataType.is_inline() {
        ((*inp).data.inline.as_ptr() as *const c_char, true)
    } else { ((*inp).data.ool, false) };
    (*outp).RetCode = trivfs_S_io_write(io_object, reply, reply_poly, data_ptr,
        (*inp).dataType.msgtl_number, offset, &mut (*outp).amount);
    if (*outp).RetCode == KERN_SUCCESS && !inline {
        mig_deallocate(data_ptr as vm_offset_t, (*inp).dataType.msgtl_number as vm_size_t);
    }
    if (*outp).RetCode != KERN_SUCCESS { return; }
    (*outp).Head.msgh_size = size_of::<Reply_write>() as u32;          // 40 i386
    (*outp).amountType = T_INTEGER_32_1;
}

#[repr(C)]
struct Req_read {
    Head: mach_msg_header_t,
    offsetType: mach_msg_type_t,
    offset: loff_t,
    amountType: mach_msg_type_t,
    amount: vm_size_t,
}

#[repr(C)]
union ReadData { inline: [u8; 2048], ool: *mut c_char }

#[repr(C)]
struct Reply_read {
    Head: mach_msg_header_t,
    RetCodeType: mach_msg_type_t,
    RetCode: kern_return_t,
    dataType: mach_msg_type_long_t,
    data: ReadData,
}

pub unsafe extern "C-unwind" fn _Xio_read(inp: *mut mach_msg_header_t, outp: *mut Reply_read) {
    let inp = inp as *const Req_read;
    if (*inp).Head.msgh_size != size_of::<Req_read>() as u32
        || (*inp).Head.msgh_bits & MACH_MSGH_BITS_COMPLEX != 0
    { mig_bad_args(outp as *mut mig_reply_header_t); return; }
    if (*inp).offsetType != T_INTEGER_64_1 { mig_bad_args(outp as *mut mig_reply_header_t); return; }
    if (*inp).amountType != T_VM_OFFSET_1 { mig_bad_args(outp as *mut mig_reply_header_t); return; }   // fix amd64 (C fija 32)

    let io_object = begin_using_io((*inp).Head.msgh_bits, (*inp).Head.msgh_local_port);
    let _guard = ProtidGuard::new(io_object);
    let reply = (*inp).Head.msgh_remote_port;
    let reply_poly = mach_msgh_bits_remote((*inp).Head.msgh_bits);
    let mut dataP: *mut c_char = (*outp).data.inline.as_mut_ptr() as *mut c_char;
    let mut dataCnt: mach_msg_type_number_t = 2048;
    (*outp).RetCode = trivfs_S_io_read(io_object, reply, reply_poly, &mut dataP, &mut dataCnt,
        (*inp).offset, (*inp).amount);
    if (*outp).RetCode != KERN_SUCCESS { return; }

    let mut msgh_simple = true;
    if dataP != (*outp).data.inline.as_mut_ptr() as *mut c_char {
        (*outp).dataType = type_desc_long_ool(MACH_MSG_TYPE_CHAR as u16, 8, dataCnt);
        (*outp).data.ool = dataP;
        msgh_simple = false;
    } else {
        (*outp).dataType = type_desc_long(MACH_MSG_TYPE_CHAR as u16, 8, dataCnt);
    }
    let data_bytes = if msgh_simple { mach_msg_align(dataCnt as usize) } else { size_of::<*const c_char>() };
    (*outp).Head.msgh_size = (size_of::<Reply_read>() - 2048 + data_bytes) as u32;
    if !msgh_simple { (*outp).Head.msgh_bits |= MACH_MSGH_BITS_COMPLEX; }
}

#[repr(C)]
union UidBuf { inline: [c_uint; 512], ool: *const c_uint }

#[repr(C)]
struct Req_restrict_auth {
    Head: mach_msg_header_t,
    uidsType: mach_msg_type_long_t,
    uids: UidBuf,
    gidsType: mach_msg_type_long_t,
    gids: UidBuf,
}

#[repr(C)]
struct Reply_restrict_auth {
    Head: mach_msg_header_t,
    RetCodeType: mach_msg_type_t,
    RetCode: kern_return_t,
    new_objectType: mach_msg_type_t,
    new_object: mach_port_t,
}

pub unsafe extern "C-unwind" fn _Xio_restrict_auth(inp: *mut mach_msg_header_t, outp: *mut Reply_restrict_auth) {
    let inp = inp as *const Req_restrict_auth;
    let base = size_of::<mach_msg_header_t>() + 2 * size_of::<mach_msg_type_long_t>();  // 48 i386 / 40 amd64
    let mut msgh_size = (*inp).Head.msgh_size;
    if msgh_size < base as u32 { mig_bad_args(outp as *mut mig_reply_header_t); return; }
    // uidsType: longform, INTEGER_32, 32
    if !(*inp).uidsType.is_longform() || (*inp).uidsType.name() != MACH_MSG_TYPE_INTEGER_32 as u16
        || (*inp).uidsType.size() != 32
    { mig_bad_args(outp as *mut mig_reply_header_t); return; }
    let uids_inline = (*inp).uidsType.is_inline();
    let delta_u = if uids_inline {
        ((*inp).uidsType.number() as u64) * 4
    } else { size_of::<*const c_uint>() as u64 };
    if (msgh_size as u64) < (base as u64) + delta_u { mig_bad_args(outp as *mut mig_reply_header_t); return; }
    msgh_size -= delta_u as u32;
    // gidsType: longform, INTEGER_32, 32 (located after the uids data)
    let tail_off = size_of::<mach_msg_header_t>() + size_of::<mach_msg_type_long_t>();
    let gids_type_ptr = (inp as *const u8).add(tail_off + delta_u as usize);
    let gids_type = *(gids_type_ptr as *const mach_msg_type_long_t);
    if !gids_type.is_longform() || gids_type.name() != MACH_MSG_TYPE_INTEGER_32 as u16
        || gids_type.size() != 32
    { mig_bad_args(outp as *mut mig_reply_header_t); return; }
    let gids_inline = gids_type.is_inline();
    let delta_g = if gids_inline {
        (gids_type.number() as u64) * 4
    } else { size_of::<*const c_uint>() as u64 };
    if (msgh_size as u64) != (base as u64) + delta_g { mig_bad_args(outp as *mut mig_reply_header_t); return; }

    let io_object = begin_using_io((*inp).Head.msgh_bits, (*inp).Head.msgh_local_port);
    let _guard = ProtidGuard::new(io_object);
    let reply = (*inp).Head.msgh_remote_port;
    let reply_poly = mach_msgh_bits_remote((*inp).Head.msgh_bits);
    let gids_pos = gids_type_ptr.add(size_of::<mach_msg_type_long_t>());
    let (uids_ptr, gids_ptr) = (
        if uids_inline { (*inp).uids.inline.as_ptr() } else { (*inp).uids.ool },
        if gids_inline { gids_pos as *const c_uint } else { *(gids_pos as *const *const c_uint) },
    );
    let mut new_objectPoly: mach_msg_type_name_t = 0;
    (*outp).RetCode = trivfs_S_io_restrict_auth(io_object, reply, reply_poly,
        &mut (*outp).new_object, &mut new_objectPoly,
        uids_ptr, (*inp).uidsType.number(), gids_ptr, gids_type.number());
    if (*outp).RetCode == KERN_SUCCESS && !gids_inline {
        mig_deallocate(gids_ptr as vm_offset_t, (4 * gids_type.number()) as vm_size_t);
    }
    if (*outp).RetCode == KERN_SUCCESS && !uids_inline {
        mig_deallocate(uids_ptr as vm_offset_t, (4 * (*inp).uidsType.number()) as vm_size_t);
    }
    if (*outp).RetCode != KERN_SUCCESS { return; }
    let mut msgh_simple = true;
    (*outp).Head.msgh_size = size_of::<Reply_restrict_auth>() as u32;   // 40 i386
    (*outp).new_objectType = type_desc(new_objectPoly, MACH_PORT_INLINE_MSGT_SIZE, 1);
    if mach_msg_type_port_any_right(new_objectPoly) { msgh_simple = false; }
    if !msgh_simple { (*outp).Head.msgh_bits |= MACH_MSGH_BITS_COMPLEX; }
}

pub const fn routine_cast<O>(f: unsafe extern "C-unwind" fn(*mut mach_msg_header_t, *mut O)) -> io_server_routine {
    unsafe { transmute(f) }
}

pub static trivfs_io_server_routines: [io_server_routine; 32] = [
    routine_cast(_Xio_write), routine_cast(_Xio_read),
    routine_cast(_Xio_seek), routine_cast(_Xio_readable),
    routine_cast(_Xio_set_all_openmodes), routine_cast(_Xio_get_openmodes),
    routine_cast(_Xio_set_some_openmodes), routine_cast(_Xio_clear_some_openmodes),
    routine_cast(_Xio_async), routine_cast(_Xio_mod_owner),
    routine_cast(_Xio_get_owner), routine_cast(_Xio_get_icky_async_id),
    routine_cast(_Xio_select), routine_cast(_Xio_stat),
    routine_cast(_Xio_reauthenticate), routine_cast(_Xio_restrict_auth),
    routine_cast(_Xio_duplicate), routine_cast(_Xio_server_version),
    routine_cast(_Xio_map), routine_cast(_Xio_map_cntl),
    routine_cast(_Xio_get_conch), routine_cast(_Xio_release_conch),
    routine_cast(_Xio_eofnotify), routine_cast(_Xio_prenotify),
    routine_cast(_Xio_postnotify), routine_cast(_Xio_readnotify),
    routine_cast(_Xio_readsleep), routine_cast(_Xio_sigio),
    routine_cast(_Xio_pathconf), routine_cast(_Xio_identity),
    routine_cast(_Xio_revoke), routine_cast(_Xio_select_timeout),
];

pub unsafe extern "C" fn trivfs_io_server(
    InHeadP: *mut mach_msg_header_t,
    OutHeadP: *mut mach_msg_header_t,
) -> boolean_t {
    let OutP = OutHeadP as *mut mig_reply_header_t;
    mig_reply_header_setup(OutP, InHeadP);                       // bits, size, remote, local=0, seqno, id+100, RetCodeType
    let id = (*InHeadP).msgh_id;
    if id > 21031 || id < 21000 {
        mig_bad_id(OutP);
        return 0;
    }
    let result = catch_unwind(AssertUnwindSafe(|| {
        trivfs_io_server_routines[(id - 21000) as usize](InHeadP, OutHeadP);
    }));
    match result {
        Ok(()) => 1,
        Err(payload) => {
            let what = if let Some(s) = payload.downcast_ref::<&str>() {
                (*s).to_string()
            } else if let Some(s) = payload.downcast_ref::<String>() {
                s.clone()
            } else {
                "unknown panic".to_string()
            };
            panic_reply(OutP, InHeadP, &what);
            1
        }
    }
}

pub fn panic_reply(outp: *mut mig_reply_header_t, inp: *mut mach_msg_header_t, what: &str) {
    // Rebuilds an EOPNOTSUPP error reply after an RPC panic:
    // the client receives the error (positive Hurd errno) and the translator
    // stays alive.
    unsafe {
        mig_reply_header_setup(outp, inp);
        (*outp).RetCode = EOPNOTSUPP;
    }
    eprintln!("[hurd-rs] RPC panicked, replying EOPNOTSUPP: {what}");
}