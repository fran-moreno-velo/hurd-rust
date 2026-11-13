#![allow(unsafe_op_in_unsafe_fn, dead_code, private_interfaces)]

//===========================================================================//
// crate::hurd::trivfs                                                       //
//---------------------------------------------------------------------------//
// From github - gnuhurd                                                     //
// /hurd/libtrivfs/generated/fsysServer.c (MIG generated)                    //
// Faithful port: 12 routines _Xfsys_* (22000-22011) + table + demuxer.     //
//===========================================================================//

use std::mem::{offset_of, size_of};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ffi::{c_char, c_int, c_void};
use libc::uid_t;

use crate::gnumach::message::{
    mach_msg_header_t, mach_msg_type_t, mach_msg_type_long_t, mach_msg_type_name_t,
    mach_msg_type_number_t, mach_msgh_bits_local, mach_msgh_bits_remote, MACH_MSGH_BITS_COMPLEX,
    mach_msg_type_port_any_right, mach_msg_align, type_desc, type_desc_long, type_desc_long_ool,
    type_desc_long_ool_nodealloc,
    MACH_MSG_TYPE_INTEGER_32, MACH_MSG_TYPE_CHAR, MACH_MSG_TYPE_PROTECTED_PAYLOAD,
    MACH_PORT_INLINE_MSGT_SIZE, MACH_PORT_INLINE_SIZE,
};
use crate::gnumach::mig::{mig_reply_header_t, mig_reply_header_setup, mig_bad_id};
use crate::gnumach::kern_return::{kern_return_t, KERN_SUCCESS};
use crate::gnumach::boolean::boolean_t;
use crate::gnumach::port::mach_port_t;
use crate::gnumach::vm_types::{vm_offset_t, vm_size_t};
use crate::gnuhurd::ports::ports_payload_get_name;
use crate::gnuhurd::types::retry_type;
use crate::gnuhurd::trivfs::types::trivfs_control_t;
use crate::gnuhurd::trivfs::mig_helpers::{
    trivfs_begin_using_control, trivfs_begin_using_control_payload, ControlGuard,
};
use crate::gnuhurd::trivfs::io_server::{
    T_INTEGER_32_1, T_STRING_C_1024, T_PORT_SEND_1, mig_deallocate, mig_bad_args,
    io_server_routine, routine_cast,
};
use crate::gnuhurd::trivfs::fsys_stubs::{
    trivfs_S_fsys_forward, trivfs_S_fsys_get_children, trivfs_S_fsys_getfile,
    trivfs_S_fsys_getpriv, trivfs_S_fsys_init, trivfs_S_fsys_startup,
    trivfs_S_fsys_syncfs, trivfs_S_fsys_get_options, trivfs_S_fsys_getroot,
    trivfs_S_fsys_goaway, trivfs_S_fsys_set_options,
};
use crate::gnuhurd::trivfs::source::trivfs_S_fsys_get_source;

//---------------------------------------------------------------------------//
// Helpers                                                                   //
//---------------------------------------------------------------------------//

// C: MACH_MSGH_BITS_LOCAL -> protected payload, else request port.
fn begin_using_control(bits: u32, port: mach_port_t) -> *mut trivfs_control_t {
    if mach_msgh_bits_local(bits) == MACH_MSG_TYPE_PROTECTED_PAYLOAD {
        trivfs_begin_using_control_payload(port as usize)
    } else {
        trivfs_begin_using_control(port)
    }
}

//---------------------------------------------------------------------------//
// Handlers trivfs_S_fsys_* which remain in C (libtrivfs.so).                //
// All ported to Rust (fsys_stubs.rs + source.rs).                            //
//---------------------------------------------------------------------------//

//---------------------------------------------------------------------------//
// Shared wire buffers (2048-byte inline / OOL pointer).                     //
//---------------------------------------------------------------------------//

#[repr(C)]
union LongBuf2048 { inline: [u8; 2048], ool: *mut c_char }
#[repr(C)]
union PortBuf512 { inline: [mach_port_t; 512], ool: *mut mach_port_t }

// Wire layout guards: offsets of the first variable segment's data and the
// fixed prefix sizes (base) must match the MIG-generated C constants.
#[cfg(target_pointer_width = "32")]
const _: () = {
    assert!(size_of::<Req_getroot>() - 2 * 2048 == 64);
    assert!(offset_of!(Req_getroot, gen_uids) == 44);
    assert!(size_of::<Req_getfile>() - 2 * 2048 == 60);
    assert!(offset_of!(Req_getfile, gen_uids) == 36);
    assert!(size_of::<Req_set_options>() - 2048 == 44);
    assert!(offset_of!(Req_set_options, options) == 36);
    assert!(size_of::<Req_forward>() - 2048 == 44);
    assert!(offset_of!(Req_forward, argv) == 44);
    assert!(size_of::<Reply_get_options>() - 2048 == 44);
    assert!(offset_of!(Reply_get_children, names) == 44);
};
#[cfg(target_pointer_width = "64")]
const _: () = {
    assert!(size_of::<Req_getroot>() - 2 * 2048 == 80);
    assert!(offset_of!(Req_getroot, gen_uids) == 56);
    assert!(size_of::<Req_getfile>() - 2 * 2048 == 56);
    assert!(offset_of!(Req_getfile, gen_uids) == 40);
    assert!(size_of::<Req_set_options>() - 2048 == 56);
    assert!(offset_of!(Req_set_options, options) == 40);
    assert!(size_of::<Req_forward>() - 2048 == 56);
    assert!(offset_of!(Req_forward, argv) == 56);
    assert!(size_of::<Reply_get_options>() - 2048 == 56);
    assert!(offset_of!(Reply_get_children, names) == 56);
};

//---------------------------------------------------------------------------//
// _Xfsys_startup                                                            //
// Req 40 (COMPLEX), Reply 40 (poly realnode).  C:58-156                     //
//---------------------------------------------------------------------------//

#[repr(C)]
struct Req_startup {
    Head: mach_msg_header_t,
    openflagsType: mach_msg_type_t,
    openflags: c_int,
    control_portType: mach_msg_type_t,
    control_port: mach_port_t,
} // 40

#[repr(C)]
struct Reply_startup {
    Head: mach_msg_header_t,
    RetCodeType: mach_msg_type_t,
    RetCode: kern_return_t,
    realnodeType: mach_msg_type_t,
    realnode: mach_port_t,
} // 40

pub unsafe extern "C-unwind" fn _Xfsys_startup(
    inp: *mut mach_msg_header_t,
    outp: *mut Reply_startup,
) {
    let inp = inp as *const Req_startup;
    if (*inp).Head.msgh_size != size_of::<Req_startup>() as u32
        || (*inp).Head.msgh_bits & MACH_MSGH_BITS_COMPLEX == 0
    { mig_bad_args(outp as *mut mig_reply_header_t); return; }
    if (*inp).openflagsType != T_INTEGER_32_1 { mig_bad_args(outp as *mut mig_reply_header_t); return; }
    if (*inp).control_portType != T_PORT_SEND_1 { mig_bad_args(outp as *mut mig_reply_header_t); return; }

    let bootstrap = if mach_msgh_bits_local((*inp).Head.msgh_bits) == MACH_MSG_TYPE_PROTECTED_PAYLOAD {
        ports_payload_get_name((*inp).Head.msgh_local_port as usize)
    } else {
        (*inp).Head.msgh_local_port
    };
    let reply = (*inp).Head.msgh_remote_port;
    let reply_poly = mach_msgh_bits_remote((*inp).Head.msgh_bits);
    let mut realnodePoly: mach_msg_type_name_t = 0;
    (*outp).RetCode = trivfs_S_fsys_startup(
        bootstrap, reply, reply_poly,
        (*inp).openflags, (*inp).control_port,
        &mut (*outp).realnode, &mut realnodePoly);
    if (*outp).RetCode != KERN_SUCCESS { return; }

    (*outp).Head.msgh_size = size_of::<Reply_startup>() as u32;
    let mut msgh_simple = true;
    (*outp).realnodeType = type_desc(realnodePoly, MACH_PORT_INLINE_MSGT_SIZE, 1);
    if mach_msg_type_port_any_right(realnodePoly) { msgh_simple = false; }
    if !msgh_simple { (*outp).Head.msgh_bits |= MACH_MSGH_BITS_COMPLEX; }
}

//---------------------------------------------------------------------------//
// _Xfsys_goaway                                                             //
// Req 32 (simple), Reply 32.  C:174-227                                     //
//---------------------------------------------------------------------------//

#[repr(C)]
struct Req_goaway {
    Head: mach_msg_header_t,
    flagsType: mach_msg_type_t,
    flags: c_int,
} // 32

pub unsafe extern "C-unwind" fn _Xfsys_goaway(
    inp: *mut mach_msg_header_t,
    outp: *mut mig_reply_header_t,
) {
    let inp = inp as *const Req_goaway;
    if (*inp).Head.msgh_size != size_of::<Req_goaway>() as u32
        || (*inp).Head.msgh_bits & MACH_MSGH_BITS_COMPLEX != 0
    { mig_bad_args(outp); return; }
    if (*inp).flagsType != T_INTEGER_32_1 { mig_bad_args(outp); return; }

    let fsys = begin_using_control((*inp).Head.msgh_bits, (*inp).Head.msgh_local_port);
    let _guard = ControlGuard::new(fsys);
    let reply = (*inp).Head.msgh_remote_port;
    let reply_poly = mach_msgh_bits_remote((*inp).Head.msgh_bits);
    (*outp).RetCode = trivfs_S_fsys_goaway(fsys, reply, reply_poly, (*inp).flags);
}

//---------------------------------------------------------------------------//
// _Xfsys_getroot                                                            //
// Req 64+d1+d2 (COMPLEX), Reply 1076.  C:242-425                            //
//---------------------------------------------------------------------------//

#[repr(C)]
struct Req_getroot {
    Head: mach_msg_header_t,
    dotdot_nodeType: mach_msg_type_t,
    dotdot_node: mach_port_t,
    gen_uidsType: mach_msg_type_long_t,
    gen_uids: LongBuf2048,
    gen_gidsType: mach_msg_type_long_t,
    gen_gids: LongBuf2048,
    flagsType: mach_msg_type_t,
    flags: c_int,
} // 4160; base wire = 64

#[repr(C)]
struct Reply_getroot {
    Head: mach_msg_header_t,
    RetCodeType: mach_msg_type_t,
    RetCode: kern_return_t,
    do_retryType: mach_msg_type_t,
    do_retry: retry_type,
    retry_nameType: mach_msg_type_t,
    retry_name: [c_char; 1024],
    fileType: mach_msg_type_t,
    file: mach_port_t,
} // 1076

pub unsafe extern "C-unwind" fn _Xfsys_getroot(
    inp: *mut mach_msg_header_t,
    outp: *mut Reply_getroot,
) {
    let inp = inp as *const Req_getroot;
    let msg = inp as *const u8;
    // Wire offsets: base = fixed prefix before the variable data
    // (size_of(Req) - the two 2048-byte inline buffers, C:64), and the first
    // segment's data sits right after gen_uidsType.
    let base = size_of::<Req_getroot>() - 2 * 2048;
    const UIDS_DATA: usize = offset_of!(Req_getroot, gen_uids);
    let mut msgh_size = (*inp).Head.msgh_size;
    if msgh_size < base as u32 || (*inp).Head.msgh_bits & MACH_MSGH_BITS_COMPLEX == 0
    { mig_bad_args(outp as *mut mig_reply_header_t); return; }
    if (*inp).dotdot_nodeType != T_PORT_SEND_1 { mig_bad_args(outp as *mut mig_reply_header_t); return; }

    // gen_uids (segm. 1): INTEGER_32/32 longform
    let gu = (*inp).gen_uidsType;
    if !gu.is_longform() || gu.name() != MACH_MSG_TYPE_INTEGER_32 as u16 || gu.size() != 32
    { mig_bad_args(outp as *mut mig_reply_header_t); return; }
    let d1 = if gu.is_inline() { (4 * gu.number()) as usize } else { size_of::<*const c_void>() };
    if msgh_size < base as u32 + d1 as u32 { mig_bad_args(outp as *mut mig_reply_header_t); return; }
    msgh_size -= d1 as u32;

    // gen_gids (segm. 2): rebase In1P = In0P + d1 - 2048
    let gpos = UIDS_DATA + d1;
    let gg = *(msg.add(gpos) as *const mach_msg_type_long_t);
    if !gg.is_longform() || gg.name() != MACH_MSG_TYPE_INTEGER_32 as u16 || gg.size() != 32
    { mig_bad_args(outp as *mut mig_reply_header_t); return; }
    let d2 = if gg.is_inline() { (4 * gg.number()) as usize } else { size_of::<*const c_void>() };
    if msgh_size != base as u32 + d2 as u32 { mig_bad_args(outp as *mut mig_reply_header_t); return; }

    // flags (segm. 3): rebase In2P = In1P + d2 - 2048
    let fpos = gpos + size_of::<mach_msg_type_long_t>() + d2;
    let ft = *(msg.add(fpos) as *const mach_msg_type_t);
    if ft != T_INTEGER_32_1 { mig_bad_args(outp as *mut mig_reply_header_t); return; }
    let flags = *(msg.add(fpos + size_of::<mach_msg_type_t>()) as *const c_int);

    let fsys = begin_using_control((*inp).Head.msgh_bits, (*inp).Head.msgh_local_port);
    let _guard = ControlGuard::new(fsys);
    let reply = (*inp).Head.msgh_remote_port;
    let reply_poly = mach_msgh_bits_remote((*inp).Head.msgh_bits);

    let uids_data: *const uid_t = if gu.is_inline() { msg.add(UIDS_DATA) as *const uid_t }
        else { *(msg.add(UIDS_DATA) as *const *const uid_t) };
    let gids_data: *const uid_t = if gg.is_inline() { msg.add(gpos + size_of::<mach_msg_type_long_t>()) as *const uid_t }
        else { *(msg.add(gpos + size_of::<mach_msg_type_long_t>()) as *const *const uid_t) };

    let mut filePoly: mach_msg_type_name_t = 0;
    (*outp).RetCode = trivfs_S_fsys_getroot(fsys, reply, reply_poly,
        (*inp).dotdot_node,
        uids_data, gu.number(), gids_data, gg.number(), flags,
        &mut (*outp).do_retry, (*outp).retry_name.as_mut_ptr(),
        &mut (*outp).file, &mut filePoly);

    // Dealloc only on KERN_SUCCESS, reverse order (gids then uids). C:399-404
    if (*outp).RetCode == KERN_SUCCESS {
        if !gg.is_inline() { mig_deallocate(gids_data as vm_offset_t, (4 * gg.number()) as vm_size_t); }
        if !gu.is_inline() { mig_deallocate(uids_data as vm_offset_t, (4 * gu.number()) as vm_size_t); }
    }
    if (*outp).RetCode != KERN_SUCCESS { return; }

    (*outp).Head.msgh_size = size_of::<Reply_getroot>() as u32;
    let mut msgh_simple = true;
    (*outp).do_retryType = T_INTEGER_32_1;
    (*outp).retry_nameType = T_STRING_C_1024;
    (*outp).fileType = type_desc(filePoly, MACH_PORT_INLINE_MSGT_SIZE, 1);
    if mach_msg_type_port_any_right(filePoly) { msgh_simple = false; }
    if !msgh_simple { (*outp).Head.msgh_bits |= MACH_MSGH_BITS_COMPLEX; }
}

//---------------------------------------------------------------------------//
// _Xfsys_getfile                                                            //
// Req 60+d1+d2+d3 (no COMPLEX check), Reply 40.  C:449-589                  //
//---------------------------------------------------------------------------//

#[repr(C)]
struct Req_getfile {
    Head: mach_msg_header_t,
    gen_uidsType: mach_msg_type_long_t,
    gen_uids: LongBuf2048,
    gen_gidsType: mach_msg_type_long_t,
    gen_gids: LongBuf2048,
    filehandleType: mach_msg_type_long_t,
} // 4156; base wire = 60

#[repr(C)]
struct Reply_getfile {
    Head: mach_msg_header_t,
    RetCodeType: mach_msg_type_t,
    RetCode: kern_return_t,
    fileType: mach_msg_type_t,
    file: mach_port_t,
} // 40

pub unsafe extern "C-unwind" fn _Xfsys_getfile(
    inp: *mut mach_msg_header_t,
    outp: *mut Reply_getfile,
) {
    let inp = inp as *const Req_getfile;
    let msg = inp as *const u8;
    let base = size_of::<Req_getfile>() - 2 * 2048;
    const UIDS_DATA: usize = offset_of!(Req_getfile, gen_uids);
    let mut msgh_size = (*inp).Head.msgh_size;
    if msgh_size < base as u32
    { mig_bad_args(outp as *mut mig_reply_header_t); return; }

    // gen_uids (segm. 1): INTEGER_32/32 longform
    let gu = (*inp).gen_uidsType;
    if !gu.is_longform() || gu.name() != MACH_MSG_TYPE_INTEGER_32 as u16 || gu.size() != 32
    { mig_bad_args(outp as *mut mig_reply_header_t); return; }
    let d1 = if gu.is_inline() { (4 * gu.number()) as usize } else { size_of::<*const c_void>() };
    if msgh_size < base as u32 + d1 as u32 { mig_bad_args(outp as *mut mig_reply_header_t); return; }
    msgh_size -= d1 as u32;

    // gen_gids (segm. 2): rebase In1P = In0P + d1 - 2048
    let gpos = UIDS_DATA + d1;
    let gg = *(msg.add(gpos) as *const mach_msg_type_long_t);
    if !gg.is_longform() || gg.name() != MACH_MSG_TYPE_INTEGER_32 as u16 || gg.size() != 32
    { mig_bad_args(outp as *mut mig_reply_header_t); return; }
    let d2 = if gg.is_inline() { (4 * gg.number()) as usize } else { size_of::<*const c_void>() };
    if msgh_size < base as u32 + d2 as u32 { mig_bad_args(outp as *mut mig_reply_header_t); return; }
    msgh_size -= d2 as u32;

    // filehandle (segm. 3): CHAR/8 longform, exact size check. C:544-554
    let fpos = gpos + size_of::<mach_msg_type_long_t>() + d2;
    let fh = *(msg.add(fpos) as *const mach_msg_type_long_t);
    if !fh.is_longform() || fh.name() != MACH_MSG_TYPE_CHAR as u16 || fh.size() != 8
    { mig_bad_args(outp as *mut mig_reply_header_t); return; }
    let d3 = if fh.is_inline() { mach_msg_align(fh.number() as usize) } else { size_of::<*const c_char>() };
    if msgh_size != base as u32 + d3 as u32 { mig_bad_args(outp as *mut mig_reply_header_t); return; }

    let fsys = begin_using_control((*inp).Head.msgh_bits, (*inp).Head.msgh_local_port);
    let _guard = ControlGuard::new(fsys);
    let reply = (*inp).Head.msgh_remote_port;
    let reply_poly = mach_msgh_bits_remote((*inp).Head.msgh_bits);

    let uids_data: *const uid_t = if gu.is_inline() { msg.add(UIDS_DATA) as *const uid_t }
        else { *(msg.add(UIDS_DATA) as *const *const uid_t) };
    let gids_data: *const uid_t = if gg.is_inline() { msg.add(gpos + size_of::<mach_msg_type_long_t>()) as *const uid_t }
        else { *(msg.add(gpos + size_of::<mach_msg_type_long_t>()) as *const *const uid_t) };
    let fh_data: *const c_char = if fh.is_inline() { msg.add(fpos + size_of::<mach_msg_type_long_t>()) as *const c_char }
        else { *(msg.add(fpos + size_of::<mach_msg_type_long_t>()) as *const *const c_char) };

    let mut filePoly: mach_msg_type_name_t = 0;
    (*outp).RetCode = trivfs_S_fsys_getfile(fsys, reply, reply_poly,
        uids_data, gu.number(), gids_data, gg.number(),
        fh_data, fh.number(), &mut (*outp).file, &mut filePoly);

    // Dealloc only on KERN_SUCCESS, reverse order (filehandle, gids, uids). C:564-572
    if (*outp).RetCode == KERN_SUCCESS {
        if !fh.is_inline() { mig_deallocate(fh_data as vm_offset_t, fh.number() as vm_size_t); }
        if !gg.is_inline() { mig_deallocate(gids_data as vm_offset_t, (4 * gg.number()) as vm_size_t); }
        if !gu.is_inline() { mig_deallocate(uids_data as vm_offset_t, (4 * gu.number()) as vm_size_t); }
    }
    if (*outp).RetCode != KERN_SUCCESS { return; }

    (*outp).Head.msgh_size = size_of::<Reply_getfile>() as u32;
    let mut msgh_simple = true;
    (*outp).fileType = type_desc(filePoly, MACH_PORT_INLINE_MSGT_SIZE, 1);
    if mach_msg_type_port_any_right(filePoly) { msgh_simple = false; }
    if !msgh_simple { (*outp).Head.msgh_bits |= MACH_MSGH_BITS_COMPLEX; }
}

//---------------------------------------------------------------------------//
// _Xfsys_syncfs                                                             //
// Req 40 (simple), Reply 32.  C:611-681                                     //
//---------------------------------------------------------------------------//

#[repr(C)]
struct Req_syncfs {
    Head: mach_msg_header_t,
    waitType: mach_msg_type_t,
    wait: c_int,
    do_childrenType: mach_msg_type_t,
    do_children: c_int,
} // 40

pub unsafe extern "C-unwind" fn _Xfsys_syncfs(
    inp: *mut mach_msg_header_t,
    outp: *mut mig_reply_header_t,
) {
    let inp = inp as *const Req_syncfs;
    if (*inp).Head.msgh_size != size_of::<Req_syncfs>() as u32
        || (*inp).Head.msgh_bits & MACH_MSGH_BITS_COMPLEX != 0
    { mig_bad_args(outp); return; }
    if (*inp).waitType != T_INTEGER_32_1 || (*inp).do_childrenType != T_INTEGER_32_1 {
        mig_bad_args(outp); return;
    }
    let fsys = begin_using_control((*inp).Head.msgh_bits, (*inp).Head.msgh_local_port);
    let _guard = ControlGuard::new(fsys);
    let reply = (*inp).Head.msgh_remote_port;
    let reply_poly = mach_msgh_bits_remote((*inp).Head.msgh_bits);
    (*outp).RetCode = trivfs_S_fsys_syncfs(fsys, reply, reply_poly, (*inp).wait, (*inp).do_children);
}

//---------------------------------------------------------------------------//
// _Xfsys_set_options                                                        //
// Req 44+d (simple), Reply 32.  C:697-782                                   //
//---------------------------------------------------------------------------//

#[repr(C)]
struct Req_set_options {
    Head: mach_msg_header_t,
    optionsType: mach_msg_type_long_t,
    options: LongBuf2048,
    do_childrenType: mach_msg_type_t,
    do_children: c_int,
} // 2092; base wire = 44

pub unsafe extern "C-unwind" fn _Xfsys_set_options(
    inp: *mut mach_msg_header_t,
    outp: *mut mig_reply_header_t,
) {
    let inp = inp as *const Req_set_options;
    let msg = inp as *const u8;
    let base = size_of::<Req_set_options>() - 1 * 2048;
    const OPTIONS_DATA: usize = offset_of!(Req_set_options, options);
    if (*inp).Head.msgh_size < base as u32
    { mig_bad_args(outp); return; }

    // options (segm. 1): CHAR/8 longform, exact size check. C:751-761
    let opts = (*inp).optionsType;
    if !opts.is_longform() || opts.name() != MACH_MSG_TYPE_CHAR as u16 || opts.size() != 8
    { mig_bad_args(outp); return; }
    let delta = if opts.is_inline() { mach_msg_align(opts.number() as usize) } else { size_of::<*const c_char>() };
    if (*inp).Head.msgh_size != base as u32 + delta as u32 { mig_bad_args(outp); return; }

    // do_children (segm. 2): rebase In1P = In0P + delta - 2048
    let dpos = OPTIONS_DATA + delta;
    let dt = *(msg.add(dpos) as *const mach_msg_type_t);
    if dt != T_INTEGER_32_1 { mig_bad_args(outp); return; }
    let do_children = *(msg.add(dpos + size_of::<mach_msg_type_t>()) as *const c_int);

    let fsys = begin_using_control((*inp).Head.msgh_bits, (*inp).Head.msgh_local_port);
    let _guard = ControlGuard::new(fsys);
    let reply = (*inp).Head.msgh_remote_port;
    let reply_poly = mach_msgh_bits_remote((*inp).Head.msgh_bits);

    let options_data: *const c_char = if opts.is_inline() { msg.add(OPTIONS_DATA) as *const c_char }
        else { *(msg.add(OPTIONS_DATA) as *const *const c_char) };
    (*outp).RetCode = trivfs_S_fsys_set_options(fsys, reply, reply_poly,
        options_data, opts.number(), do_children);
    if (*outp).RetCode == KERN_SUCCESS && !opts.is_inline() {
        mig_deallocate(options_data as vm_offset_t, opts.number() as vm_size_t);   // C: __mig_deallocate
    }
}

//---------------------------------------------------------------------------//
// _Xfsys_getpriv                                                            //
// Req 24 (simple), Reply 56 (3 poly).  C:799-907                            //
//---------------------------------------------------------------------------//

#[repr(C)]
struct Reply_getpriv {
    Head: mach_msg_header_t,
    RetCodeType: mach_msg_type_t,
    RetCode: kern_return_t,
    host_privType: mach_msg_type_t,
    host_priv: mach_port_t,
    device_masterType: mach_msg_type_t,
    device_master: mach_port_t,
    fstaskType: mach_msg_type_t,
    fstask: mach_port_t,
} // 56

pub unsafe extern "C-unwind" fn _Xfsys_getpriv(
    inp: *mut mach_msg_header_t,
    outp: *mut Reply_getpriv,
) {
    if (*inp).msgh_size != size_of::<mach_msg_header_t>() as u32
        || (*inp).msgh_bits & MACH_MSGH_BITS_COMPLEX != 0 {
        mig_bad_args(outp as *mut mig_reply_header_t);
        return;
    }
    let fsys = begin_using_control((*inp).msgh_bits, (*inp).msgh_local_port);
    let _guard = ControlGuard::new(fsys);
    let reply = (*inp).msgh_remote_port;
    let reply_poly = mach_msgh_bits_remote((*inp).msgh_bits);
    let mut host_privPoly: mach_msg_type_name_t = 0;
    let mut device_masterPoly: mach_msg_type_name_t = 0;
    let mut fstaskPoly: mach_msg_type_name_t = 0;
    (*outp).RetCode = trivfs_S_fsys_getpriv(
        fsys, reply, reply_poly,
        &mut (*outp).host_priv, &mut host_privPoly,
        &mut (*outp).device_master, &mut device_masterPoly,
        &mut (*outp).fstask, &mut fstaskPoly);
    if (*outp).RetCode != KERN_SUCCESS { return; }

    (*outp).Head.msgh_size = size_of::<Reply_getpriv>() as u32;
    let mut msgh_simple = true;
    (*outp).host_privType = type_desc(host_privPoly, MACH_PORT_INLINE_MSGT_SIZE, 1);
    if mach_msg_type_port_any_right(host_privPoly) { msgh_simple = false; }
    (*outp).device_masterType = type_desc(device_masterPoly, MACH_PORT_INLINE_MSGT_SIZE, 1);
    if mach_msg_type_port_any_right(device_masterPoly) { msgh_simple = false; }
    (*outp).fstaskType = type_desc(fstaskPoly, MACH_PORT_INLINE_MSGT_SIZE, 1);
    if mach_msg_type_port_any_right(fstaskPoly) { msgh_simple = false; }
    if !msgh_simple { (*outp).Head.msgh_bits |= MACH_MSGH_BITS_COMPLEX; }
}

//---------------------------------------------------------------------------//
// _Xfsys_init                                                               //
// Req 40 (COMPLEX), Reply 32.  C:927-1000                                   //
//---------------------------------------------------------------------------//

#[repr(C)]
struct Req_init {
    Head: mach_msg_header_t,
    proc_serverType: mach_msg_type_t,
    proc_server: mach_port_t,
    auth_handleType: mach_msg_type_t,
    auth_handle: mach_port_t,
} // 40

pub unsafe extern "C-unwind" fn _Xfsys_init(
    inp: *mut mach_msg_header_t,
    outp: *mut mig_reply_header_t,
) {
    let inp = inp as *const Req_init;
    if (*inp).Head.msgh_size != size_of::<Req_init>() as u32
        || (*inp).Head.msgh_bits & MACH_MSGH_BITS_COMPLEX == 0
    { mig_bad_args(outp); return; }
    if (*inp).proc_serverType != T_PORT_SEND_1 { mig_bad_args(outp); return; }
    if (*inp).auth_handleType != T_PORT_SEND_1 { mig_bad_args(outp); return; }

    let fsys = begin_using_control((*inp).Head.msgh_bits, (*inp).Head.msgh_local_port);
    let _guard = ControlGuard::new(fsys);
    let reply_port = (*inp).Head.msgh_remote_port;
    let reply_port_poly = mach_msgh_bits_remote((*inp).Head.msgh_bits);
    (*outp).RetCode = trivfs_S_fsys_init(fsys, reply_port, reply_port_poly,
        (*inp).proc_server, (*inp).auth_handle);
}

//---------------------------------------------------------------------------//
// _Xfsys_forward                                                            //
// Req 44+d (COMPLEX), Reply 32.  No begin/end_using_control.  C:1016-1090   //
//---------------------------------------------------------------------------//

#[repr(C)]
struct Req_forward {
    Head: mach_msg_header_t,
    requestorType: mach_msg_type_t,
    requestor: mach_port_t,
    argvType: mach_msg_type_long_t,
    argv: LongBuf2048,
} // 2092; base wire = 44

pub unsafe extern "C-unwind" fn _Xfsys_forward(
    inp: *mut mach_msg_header_t,
    outp: *mut mig_reply_header_t,
) {
    let inp = inp as *const Req_forward;
    let msg = inp as *const u8;
    let base = size_of::<Req_forward>() - 1 * 2048;
    const ARGV_DATA: usize = offset_of!(Req_forward, argv);
    if (*inp).Head.msgh_size < base as u32
        || (*inp).Head.msgh_bits & MACH_MSGH_BITS_COMPLEX == 0
    { mig_bad_args(outp); return; }
    if (*inp).requestorType != T_PORT_SEND_1 { mig_bad_args(outp); return; }

    // argv (segm. 1): CHAR/8 longform, exact size check. C:1068-1078
    let argv = (*inp).argvType;
    if !argv.is_longform() || argv.name() != MACH_MSG_TYPE_CHAR as u16 || argv.size() != 8
    { mig_bad_args(outp); return; }
    let delta = if argv.is_inline() { mach_msg_align(argv.number() as usize) } else { size_of::<*const c_char>() };
    if (*inp).Head.msgh_size != base as u32 + delta as u32 { mig_bad_args(outp); return; }

    // C:1080-1084: payload bootstrap, no begin_using_control.
    let server = if mach_msgh_bits_local((*inp).Head.msgh_bits) == MACH_MSG_TYPE_PROTECTED_PAYLOAD {
        ports_payload_get_name((*inp).Head.msgh_local_port as usize)
    } else {
        (*inp).Head.msgh_local_port
    };
    let reply = (*inp).Head.msgh_remote_port;
    let reply_poly = mach_msgh_bits_remote((*inp).Head.msgh_bits);

    let argv_data: *const c_char = if argv.is_inline() { msg.add(ARGV_DATA) as *const c_char }
        else { *(msg.add(ARGV_DATA) as *const *const c_char) };
    (*outp).RetCode = trivfs_S_fsys_forward(server, reply, reply_poly,
        (*inp).requestor, argv_data, argv.number());
    if (*outp).RetCode == KERN_SUCCESS && !argv.is_inline() {
        mig_deallocate(argv_data as vm_offset_t, argv.number() as vm_size_t);
    }
}

//---------------------------------------------------------------------------//
// _Xfsys_get_options                                                        //
// Req 24 (simple), Reply 44+d longform CHAR/8.  C:1107-1188                 //
//---------------------------------------------------------------------------//

#[repr(C)]
struct Reply_get_options {
    Head: mach_msg_header_t,
    RetCodeType: mach_msg_type_t,
    RetCode: kern_return_t,
    optionsType: mach_msg_type_long_t,
    options: LongBuf2048,
} // wire msgh_size = size_of::<Reply>() - 2048 + delta

pub unsafe extern "C-unwind" fn _Xfsys_get_options(
    inp: *mut mach_msg_header_t,
    outp: *mut Reply_get_options,
) {
    if (*inp).msgh_size != size_of::<mach_msg_header_t>() as u32
        || (*inp).msgh_bits & MACH_MSGH_BITS_COMPLEX != 0 {
        mig_bad_args(outp as *mut mig_reply_header_t);
        return;
    }
    let fsys = begin_using_control((*inp).msgh_bits, (*inp).msgh_local_port);
    let _guard = ControlGuard::new(fsys);
    let reply = (*inp).msgh_remote_port;
    let reply_poly = mach_msgh_bits_remote((*inp).msgh_bits);

    let mut optionsP: *mut c_char = (*outp).options.inline.as_mut_ptr() as *mut c_char;
    let mut optionsCnt: mach_msg_type_number_t = 2048;
    (*outp).RetCode = trivfs_S_fsys_get_options(fsys, reply, reply_poly,
        &mut optionsP, &mut optionsCnt);
    if (*outp).RetCode != KERN_SUCCESS { return; }

    let mut msgh_simple = true;
    if optionsP != (*outp).options.inline.as_mut_ptr() as *mut c_char {
        (*outp).optionsType = type_desc_long_ool(MACH_MSG_TYPE_CHAR as u16, 8, optionsCnt);
        (*outp).options.ool = optionsP;
        msgh_simple = false;
    } else {
        (*outp).optionsType = type_desc_long(MACH_MSG_TYPE_CHAR as u16, 8, optionsCnt);
    }
    let delta = if msgh_simple { mach_msg_align(optionsCnt as usize) } else { size_of::<*const c_char>() };
    (*outp).Head.msgh_size = (size_of::<Reply_get_options>() - 2048 + delta) as u32;
    if !msgh_simple { (*outp).Head.msgh_bits |= MACH_MSGH_BITS_COMPLEX; }
}

//---------------------------------------------------------------------------//
// _Xfsys_get_children                                                       //
// Req 24 (simple), Reply 56+dn+dc (names CHAR/8, controls POLY/32).         //
// C:1204-1339                                                               //
//---------------------------------------------------------------------------//

#[repr(C)]
struct Reply_get_children {
    Head: mach_msg_header_t,
    RetCodeType: mach_msg_type_t,
    RetCode: kern_return_t,
    namesType: mach_msg_type_long_t,
    names: LongBuf2048,
    controlsType: mach_msg_type_long_t,
    controls: PortBuf512,
} // 4152; wire msgh_size = 56 + dn + dc

pub unsafe extern "C-unwind" fn _Xfsys_get_children(
    inp: *mut mach_msg_header_t,
    outp: *mut Reply_get_children,
) {
    if (*inp).msgh_size != size_of::<mach_msg_header_t>() as u32
        || (*inp).msgh_bits & MACH_MSGH_BITS_COMPLEX != 0 {
        mig_bad_args(outp as *mut mig_reply_header_t);
        return;
    }
    let fsys = begin_using_control((*inp).msgh_bits, (*inp).msgh_local_port);
    let _guard = ControlGuard::new(fsys);
    let reply = (*inp).msgh_remote_port;
    let reply_poly = mach_msgh_bits_remote((*inp).msgh_bits);

    let mut namesP: *mut c_char = (*outp).names.inline.as_mut_ptr() as *mut c_char;
    let mut namesCnt: mach_msg_type_number_t = 2048;
    let mut controls_local: [mach_port_t; 512] = [0; 512];
    let mut controlsP: *mut mach_port_t = controls_local.as_mut_ptr();
    let mut controlsPoly: mach_msg_type_name_t = 0;
    let mut controlsCnt: mach_msg_type_number_t = 512;
    (*outp).RetCode = trivfs_S_fsys_get_children(fsys, reply, reply_poly,
        &mut namesP, &mut namesCnt,
        &mut controlsP, &mut controlsPoly, &mut controlsCnt);
    if (*outp).RetCode != KERN_SUCCESS { return; }

    let out = outp as *mut u8;
    let mut msgh_simple = true;

    // names (segm. 1, in struct): CHAR/8. C:1302-1310
    let names_ool = namesP != (*outp).names.inline.as_mut_ptr() as *mut c_char;
    if names_ool {
        (*outp).namesType = type_desc_long_ool_nodealloc(MACH_MSG_TYPE_CHAR as u16, 8, namesCnt);
        (*outp).names.ool = namesP;
        msgh_simple = false;
    } else {
        (*outp).namesType = type_desc_long(MACH_MSG_TYPE_CHAR as u16, 8, namesCnt);
    }
    let dn = if names_ool { size_of::<*const c_char>() } else { mach_msg_align(namesCnt as usize) };
    let mut msgh_size = size_of::<mach_msg_header_t>() + size_of::<mach_msg_type_t>()
        + size_of::<kern_return_t>() + 2 * size_of::<mach_msg_type_long_t>() + dn;

    // controls (segm. 2): rebase OutP += dn - 2048. POLY/32 longform. C:1314-1333
    let cpos = offset_of!(Reply_get_children, names) + dn;
    let controls_inline = controlsP == controls_local.as_mut_ptr();
    if controls_inline {
        *(out.add(cpos) as *mut mach_msg_type_long_t) = type_desc_long(controlsPoly as u16, MACH_PORT_INLINE_MSGT_SIZE, controlsCnt);
        if controlsCnt != 0 {
            std::ptr::copy_nonoverlapping(controls_local.as_ptr(),
                out.add(cpos + size_of::<mach_msg_type_long_t>()) as *mut mach_port_t,
                controlsCnt as usize);
        }
    } else {
        *(out.add(cpos) as *mut mach_msg_type_long_t) =
            type_desc_long_ool_nodealloc(controlsPoly as u16, 32, controlsCnt);
        *(out.add(cpos + size_of::<mach_msg_type_long_t>()) as *mut *mut mach_port_t) = controlsP;
        msgh_simple = false;
    }
    if mach_msg_type_port_any_right(controlsPoly) { msgh_simple = false; }

    let dc = if controls_inline { MACH_PORT_INLINE_SIZE * controlsCnt as usize } else { size_of::<*const mach_port_t>() };
    msgh_size += dc;

    (*outp).Head.msgh_size = msgh_size as u32;
    if !msgh_simple { (*outp).Head.msgh_bits |= MACH_MSGH_BITS_COMPLEX; }
}

//---------------------------------------------------------------------------//
// _Xfsys_get_source                                                         //
// Req 24 (simple), Reply 1060 (STRING_C/1024).  C:1358-1413                 //
//---------------------------------------------------------------------------//

#[repr(C)]
struct Reply_get_source {
    Head: mach_msg_header_t,
    RetCodeType: mach_msg_type_t,
    RetCode: kern_return_t,
    sourceType: mach_msg_type_t,
    source: [c_char; 1024],
} // 1060

pub unsafe extern "C-unwind" fn _Xfsys_get_source(
    inp: *mut mach_msg_header_t,
    outp: *mut Reply_get_source,
) {
    if (*inp).msgh_size != size_of::<mach_msg_header_t>() as u32
        || (*inp).msgh_bits & MACH_MSGH_BITS_COMPLEX != 0 {
        mig_bad_args(outp as *mut mig_reply_header_t);
        return;
    }
    let fsys = begin_using_control((*inp).msgh_bits, (*inp).msgh_local_port);
    let _guard = ControlGuard::new(fsys);
    let reply = (*inp).msgh_remote_port;
    let reply_poly = mach_msgh_bits_remote((*inp).msgh_bits);
    (*outp).RetCode = trivfs_S_fsys_get_source(fsys, reply, reply_poly, (*outp).source.as_mut_ptr());
    if (*outp).RetCode != KERN_SUCCESS { return; }

    (*outp).Head.msgh_size = size_of::<Reply_get_source>() as u32;
    (*outp).sourceType = T_STRING_C_1024;
}

//---------------------------------------------------------------------------//
// Server table + demuxer.  C:1427-1477                                      //
//---------------------------------------------------------------------------//

pub static trivfs_fsys_server_routines: [io_server_routine; 12] = [
    routine_cast(_Xfsys_startup),             // 22000
    routine_cast(_Xfsys_goaway),              // 22001
    routine_cast(_Xfsys_getroot),             // 22002
    routine_cast(_Xfsys_getfile),             // 22003
    routine_cast(_Xfsys_syncfs),              // 22004
    routine_cast(_Xfsys_set_options),         // 22005
    routine_cast(_Xfsys_getpriv),             // 22006
    routine_cast(_Xfsys_init),                // 22007
    routine_cast(_Xfsys_forward),             // 22008
    routine_cast(_Xfsys_get_options),         // 22009
    routine_cast(_Xfsys_get_children),        // 22010
    routine_cast(_Xfsys_get_source),          // 22011
];

#[unsafe(no_mangle)]
pub unsafe extern "C" fn trivfs_fsys_server(
    InHeadP: *mut mach_msg_header_t,
    OutHeadP: *mut mach_msg_header_t,
) -> boolean_t {
    let OutP = OutHeadP as *mut mig_reply_header_t;
    mig_reply_header_setup(OutP, InHeadP);        // bits/size/remote/local=0/seqno/id+100/RetCodeType
    let id = (*InHeadP).msgh_id;
    if id > 22011 || id < 22000 {
        mig_bad_id(OutP);                          // C:1470
        return 0;
    }
    let result = catch_unwind(AssertUnwindSafe(|| {
        trivfs_fsys_server_routines[(id - 22000) as usize](InHeadP, OutHeadP);
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
            crate::gnuhurd::trivfs::io_server::panic_reply(OutP, InHeadP, &what);
            1
        }
    }
}
