#![allow(unsafe_op_in_unsafe_fn, dead_code, private_interfaces)]

use std::mem::{offset_of, size_of};
use std::panic::{catch_unwind, AssertUnwindSafe};
use crate::gnumach::message::{
    mach_msg_header_t, mach_msg_type_t, mach_msg_type_name_t, mach_msgh_bits_remote,
    MACH_MSGH_BITS_COMPLEX, mach_msg_type_port_any_right, type_desc, MACH_MSG_TYPE_INTEGER_32,
    mach_msg_type_long_t, mach_msg_type_number_t, type_desc_long, type_desc_long_ool,
    type_desc_long_ool_nodealloc,
    MACH_MSG_TYPE_CHAR, MACH_MSG_TYPE_PORT_SEND, MACH_MSG_TYPE_PORT_NAME,
    MACH_MSG_TYPE_INTEGER_64, MACH_PORT_INLINE_MSGT_SIZE, MACH_PORT_INLINE_SIZE,
    mach_msg_align
};
use crate::gnumach::mig::{mig_reply_header_t, mig_reply_header_setup, mig_bad_id};
use crate::gnuhurd::trivfs::mig_helpers::{trivfs_begin_using_protid, ProtidGuard};
use std::ffi::{c_int, c_char, c_void};
use crate::gnumach::port::{mach_port_t, mach_port_name_t};
use crate::gnumach::kern_return::{kern_return_t, KERN_SUCCESS};      
use crate::gnuhurd::trivfs::file::{
    trivfs_S_file_chown, trivfs_S_file_chmod, trivfs_S_file_utimes,
    trivfs_S_file_sync, trivfs_S_file_set_size,trivfs_S_file_statfs, flock_t,
    trivfs_S_file_exec, trivfs_S_file_exec_paths, trivfs_S_file_getfh,
    trivfs_S_file_get_translator, trivfs_S_file_get_translator_cntl,
    trivfs_S_file_lock, trivfs_S_file_lock_stat, trivfs_S_file_notice_changes,
    trivfs_S_file_record_lock, trivfs_S_file_chflags, trivfs_S_file_chauthor,
    trivfs_S_file_syncfs, trivfs_S_file_getcontrol, trivfs_S_file_getlinknode,
    trivfs_S_file_get_fs_options, trivfs_S_file_reparent,
    trivfs_S_file_get_storage_info, trivfs_S_file_utimens,
};
use crate::gnuhurd::trivfs::dir::{
    trivfs_S_dir_notice_changes, trivfs_S_dir_link, trivfs_S_dir_lookup,
    trivfs_S_dir_readdir, trivfs_S_dir_mkfile, trivfs_S_dir_mkdir,
    trivfs_S_dir_rmdir, trivfs_S_dir_unlink, trivfs_S_dir_rename,
};
use crate::gnuhurd::trivfs::times::{time_value_t, timespec_t};
use crate::gnuhurd::trivfs::ioctl::{trivfs_S_file_check_access, trivfs_S_file_set_translator};
use crate::gnuhurd::io::{loff_t, fsys_statfsbuf_t};
use crate::gnumach::vm_types::{vm_offset_t, vm_size_t};
use crate::gnumach::boolean::boolean_t;
use crate::gnuhurd::trivfs::io_server::{
    T_INTEGER_32_1, T_INTEGER_32_2, T_INTEGER_64_1, begin_using_io, mig_bad_args,
    T_PORT_SEND_1, T_STRING_C_1024, mig_deallocate, T_TIMESPEC,
    io_server_routine, routine_cast                        
};

//---------------------------------------------------------------------------//
// Handlers trivfs_S_file_* which remain in C (libtrivfs.so).               //
// We will remove one by one once ported to Rust.                            //
//---------------------------------------------------------------------------//

#[repr(C)]
union LongBuf2048 {
    inline: [u8; 2048],
    ool: *mut c_char,
}

// Handlers trivfs_S_* all ported to Rust (dir.rs / file.rs / ioctl.rs).

// flock_t (definido en file.rs, re-exportado e importado arriba)

#[repr(C)]
struct Req_chown {
    Head: mach_msg_header_t,
    new_ownerType: mach_msg_type_t,
    new_owner: u32,             // uid_t
    new_groupType: mach_msg_type_t,
    new_group: u32,             // gid_t
} // size_of = 40 == check C:378

pub unsafe extern "C-unwind" fn _Xfile_chown(
    inp: *mut mach_msg_header_t,
    outp: *mut mig_reply_header_t,
) {
    let inp = inp as *const Req_chown;
    if (*inp).Head.msgh_size != size_of::<Req_chown>() as u32
        || (*inp).Head.msgh_bits & MACH_MSGH_BITS_COMPLEX != 0 {
        mig_bad_args(outp);
        return;
    }
    if (*inp).new_ownerType != T_INTEGER_32_1 || (*inp).new_groupType != T_INTEGER_32_1 {
        mig_bad_args(outp);
        return;
    }
    let cred = begin_using_io((*inp).Head.msgh_bits, (*inp).Head.msgh_local_port);
    let _guard = ProtidGuard::new(cred);
    let reply = (*inp).Head.msgh_remote_port;
    let reply_poly = mach_msgh_bits_remote((*inp).Head.msgh_bits);
    (*outp).RetCode = trivfs_S_file_chown(cred, reply, reply_poly, (*inp).new_owner, (*inp).new_group);
}

#[repr(C)]
struct Req_chmod {
    Head: mach_msg_header_t,
    new_modeType: mach_msg_type_t,
    new_mode: u32,          // mode_t
} // size_of = 32 == check C:520

pub unsafe extern "C-unwind" fn _Xfile_chmod(
    inp: *mut mach_msg_header_t,
    outp: *mut mig_reply_header_t,
) {
    let inp = inp as *const Req_chmod;
    if (*inp).Head.msgh_size != size_of::<Req_chmod>() as u32
        || (*inp).Head.msgh_bits & MACH_MSGH_BITS_COMPLEX != 0 {
        mig_bad_args(outp);
        return;
    }
    if (*inp).new_modeType != T_INTEGER_32_1 {
        mig_bad_args(outp);
        return;
    }
    let cred = begin_using_io((*inp).Head.msgh_bits, (*inp).Head.msgh_local_port);
    let _guard = ProtidGuard::new(cred);
    let reply = (*inp).Head.msgh_remote_port;
    let reply_poly = mach_msgh_bits_remote((*inp).Head.msgh_bits);
    (*outp).RetCode = trivfs_S_file_chmod(cred, reply, reply_poly, (*inp).new_mode as c_int);
}

#[repr(C)]
struct Req_chflags {
    Head: mach_msg_header_t,
    new_flagsType: mach_msg_type_t,
    new_flags: c_int,
} // size_of = 32 == check C:588

pub unsafe extern "C-unwind" fn _Xfile_chflags(
    inp: *mut mach_msg_header_t,
    outp: *mut mig_reply_header_t,
) {
    let inp = inp as *const Req_chflags;
    if (*inp).Head.msgh_size != size_of::<Req_chflags>() as u32
        || (*inp).Head.msgh_bits & MACH_MSGH_BITS_COMPLEX != 0 {
        mig_bad_args(outp);
        return;
    }
    if (*inp).new_flagsType != T_INTEGER_32_1 {
        mig_bad_args(outp);
        return;
    }
    let cred = begin_using_io((*inp).Head.msgh_bits, (*inp).Head.msgh_local_port);
    let _guard = ProtidGuard::new(cred);
    let reply = (*inp).Head.msgh_remote_port;
    let reply_poly = mach_msgh_bits_remote((*inp).Head.msgh_bits);
    (*outp).RetCode = trivfs_S_file_chflags(cred, reply, reply_poly, (*inp).new_flags);
}

#[repr(C)]
struct Req_utimes {
    Head: mach_msg_header_t,
    new_atimeType: mach_msg_type_t,
    new_atime: time_value_t,       // 8 B
    new_mtimeType: mach_msg_type_t,
    new_mtime: time_value_t,
} // size_of = 48 == check C:668

pub unsafe extern "C-unwind" fn _Xfile_utimes(
    inp: *mut mach_msg_header_t,
    outp: *mut mig_reply_header_t,
) {
    let inp = inp as *const Req_utimes;
    if (*inp).Head.msgh_size != size_of::<Req_utimes>() as u32
        || (*inp).Head.msgh_bits & MACH_MSGH_BITS_COMPLEX != 0 {
        mig_bad_args(outp);
        return;
    }
    if (*inp).new_atimeType != T_INTEGER_32_2 || (*inp).new_mtimeType != T_INTEGER_32_2 {
        mig_bad_args(outp);
        return;
    }
    let cred = begin_using_io((*inp).Head.msgh_bits, (*inp).Head.msgh_local_port);
    let _guard = ProtidGuard::new(cred);
    let reply = (*inp).Head.msgh_remote_port;
    let reply_poly = mach_msgh_bits_remote((*inp).Head.msgh_bits);
    (*outp).RetCode = trivfs_S_file_utimes(cred, reply, reply_poly, (*inp).new_atime, (*inp).new_mtime);
}

#[repr(C)]
struct Req_set_size {
    Head: mach_msg_header_t,
    new_sizeType: mach_msg_type_t,
    new_size: loff_t,          // 8 B
} // size_of = 36 == check C:742

pub unsafe extern "C-unwind" fn _Xfile_set_size(
    inp: *mut mach_msg_header_t,
    outp: *mut mig_reply_header_t,
) {
    let inp = inp as *const Req_set_size;
    if (*inp).Head.msgh_size != size_of::<Req_set_size>() as u32
        || (*inp).Head.msgh_bits & MACH_MSGH_BITS_COMPLEX != 0 {
        mig_bad_args(outp);
        return;
    }
    if (*inp).new_sizeType != T_INTEGER_64_1 {
        mig_bad_args(outp);
        return;
    }
    let cred = begin_using_io((*inp).Head.msgh_bits, (*inp).Head.msgh_local_port);
    let _guard = ProtidGuard::new(cred);
    let reply = (*inp).Head.msgh_remote_port;
    let reply_poly = mach_msgh_bits_remote((*inp).Head.msgh_bits);
    (*outp).RetCode = trivfs_S_file_set_size(cred, reply, reply_poly, (*inp).new_size);
}

#[repr(C)]
struct Req_sync {
    Head: mach_msg_header_t,
    waitType: mach_msg_type_t,
    wait: c_int,
    omit_metadataType: mach_msg_type_t,
    omit_metadata: c_int,
} // size_of = 40 == check C:1266

pub unsafe extern "C-unwind" fn _Xfile_sync(
    inp: *mut mach_msg_header_t,
    outp: *mut mig_reply_header_t,
) {
    let inp = inp as *const Req_sync;
    if (*inp).Head.msgh_size != size_of::<Req_sync>() as u32
        || (*inp).Head.msgh_bits & MACH_MSGH_BITS_COMPLEX != 0 {
        mig_bad_args(outp);
        return;
    }
    if (*inp).waitType != T_INTEGER_32_1 || (*inp).omit_metadataType != T_INTEGER_32_1 {
        mig_bad_args(outp);
        return;
    }
    let cred = begin_using_io((*inp).Head.msgh_bits, (*inp).Head.msgh_local_port);
    let _guard = ProtidGuard::new(cred);
    let reply = (*inp).Head.msgh_remote_port;
    let reply_poly = mach_msgh_bits_remote((*inp).Head.msgh_bits);
    (*outp).RetCode = trivfs_S_file_sync(cred, reply, reply_poly, (*inp).wait, (*inp).omit_metadata);
}

#[repr(C)]
struct Reply_check_access {
    Head: mach_msg_header_t,
    RetCodeType: mach_msg_type_t,
    RetCode: kern_return_t,
    allowedType: mach_msg_type_t,
    allowed: c_int,
} // size_of = 40 == msgh_size fixed by C:982

pub unsafe extern "C-unwind" fn _Xfile_check_access(
    inp: *mut mach_msg_header_t,
    outp: *mut Reply_check_access,
) {
    if (*inp).msgh_size != size_of::<mach_msg_header_t>() as u32
        || (*inp).msgh_bits & MACH_MSGH_BITS_COMPLEX != 0 {
        mig_bad_args(outp as *mut mig_reply_header_t);
        return;
    }
    let cred = begin_using_io((*inp).msgh_bits, (*inp).msgh_local_port);
    let _guard = ProtidGuard::new(cred);
    let reply = (*inp).msgh_remote_port;
    let reply_poly = mach_msgh_bits_remote((*inp).msgh_bits);
    (*outp).RetCode = trivfs_S_file_check_access(cred, reply, reply_poly, &mut (*outp).allowed);
    if (*outp).RetCode != KERN_SUCCESS {
        return;
    }
    (*outp).Head.msgh_size = size_of::<Reply_check_access>() as u32;
    (*outp).allowedType = T_INTEGER_32_1;
}

#[repr(C)]
struct Reply_lock_stat {
    Head: mach_msg_header_t,
    RetCodeType: mach_msg_type_t,
    RetCode: kern_return_t,
    mystatusType: mach_msg_type_t,
    mystatus: c_int,
    otherstatusType: mach_msg_type_t,
    otherstatus: c_int,
} // size_of = 48 == C:909

pub unsafe extern "C-unwind" fn _Xfile_lock_stat(
    inp: *mut mach_msg_header_t,
    outp: *mut Reply_lock_stat,
) {
    if (*inp).msgh_size != size_of::<mach_msg_header_t>() as u32
        || (*inp).msgh_bits & MACH_MSGH_BITS_COMPLEX != 0 {
        mig_bad_args(outp as *mut mig_reply_header_t);
        return;
    }
    let cred = begin_using_io((*inp).msgh_bits, (*inp).msgh_local_port);
    let _guard = ProtidGuard::new(cred);
    let reply = (*inp).msgh_remote_port;
    let reply_poly = mach_msgh_bits_remote((*inp).msgh_bits);
    (*outp).RetCode = trivfs_S_file_lock_stat(
        cred, reply, reply_poly, &mut (*outp).mystatus, &mut (*outp).otherstatus,
    );
    if (*outp).RetCode != KERN_SUCCESS { return; }
    (*outp).Head.msgh_size = size_of::<Reply_lock_stat>() as u32;
    (*outp).mystatusType = T_INTEGER_32_1;
    (*outp).otherstatusType = T_INTEGER_32_1;
}

const T_INTEGER_32_22: mach_msg_type_t = type_desc(MACH_MSG_TYPE_INTEGER_32, 32, 22);
const T_INTEGER_32_7: mach_msg_type_t = type_desc(MACH_MSG_TYPE_INTEGER_32, 32, 7);

#[repr(C)]
struct Reply_statfs {
    Head: mach_msg_header_t,
    RetCodeType: mach_msg_type_t,
    RetCode: kern_return_t,
    infoType: mach_msg_type_t,
    info: fsys_statfsbuf_t,
} // size_of = 124 == C:1202

pub unsafe extern "C-unwind" fn _Xfile_statfs(
    inp: *mut mach_msg_header_t,
    outp: *mut Reply_statfs,
) {
    if (*inp).msgh_size != size_of::<mach_msg_header_t>() as u32
        || (*inp).msgh_bits & MACH_MSGH_BITS_COMPLEX != 0 {
        mig_bad_args(outp as *mut mig_reply_header_t);
        return;
    }
    let cred = begin_using_io((*inp).msgh_bits, (*inp).msgh_local_port);
    let _guard = ProtidGuard::new(cred);
    let reply = (*inp).msgh_remote_port;
    let reply_poly = mach_msgh_bits_remote((*inp).msgh_bits);
    (*outp).RetCode = trivfs_S_file_statfs(cred, reply, reply_poly, &mut (*outp).info);
    if (*outp).RetCode != KERN_SUCCESS { return; }
    (*outp).Head.msgh_size = size_of::<Reply_statfs>() as u32;
    (*outp).infoType = T_INTEGER_32_22;
}

#[repr(C)]
struct Reply_getlinknode {
    Head: mach_msg_header_t,
    RetCodeType: mach_msg_type_t,
    RetCode: kern_return_t,
    linknodeType: mach_msg_type_t,
    linknode: mach_port_t,
} // size_of = 40 == C:1697

pub unsafe extern "C-unwind" fn _Xfile_getlinknode(
    inp: *mut mach_msg_header_t,
    outp: *mut Reply_getlinknode,
) {
    if (*inp).msgh_size != size_of::<mach_msg_header_t>() as u32
        || (*inp).msgh_bits & MACH_MSGH_BITS_COMPLEX != 0 {
        mig_bad_args(outp as *mut mig_reply_header_t);
        return;
    }
    let cred = begin_using_io((*inp).msgh_bits, (*inp).msgh_local_port);
    let _guard = ProtidGuard::new(cred);
    let reply = (*inp).msgh_remote_port;
    let reply_poly = mach_msgh_bits_remote((*inp).msgh_bits);
    let mut linknodePoly: mach_msg_type_name_t = 0;
    (*outp).RetCode = trivfs_S_file_getlinknode(
        cred, reply, reply_poly, &mut (*outp).linknode, &mut linknodePoly,
    );
    if (*outp).RetCode != KERN_SUCCESS { return; }
    (*outp).Head.msgh_size = size_of::<Reply_getlinknode>() as u32;
    let mut msgh_simple = true;
    (*outp).linknodeType = type_desc(linknodePoly, MACH_PORT_INLINE_MSGT_SIZE, 1);
    if mach_msg_type_port_any_right(linknodePoly) { msgh_simple = false; }
    if !msgh_simple { (*outp).Head.msgh_bits |= MACH_MSGH_BITS_COMPLEX; }
}

#[repr(C)]
struct Reply_getcontrol {
    Head: mach_msg_header_t,
    RetCodeType: mach_msg_type_t,
    RetCode: kern_return_t,
    controlType: mach_msg_type_t,
    control: mach_port_t,
} // size_of = 40 == C:1123

pub unsafe extern "C-unwind" fn _Xfile_getcontrol(
    inp: *mut mach_msg_header_t,
    outp: *mut Reply_getcontrol,
) {
    if (*inp).msgh_size != size_of::<mach_msg_header_t>() as u32
        || (*inp).msgh_bits & MACH_MSGH_BITS_COMPLEX != 0 {
        mig_bad_args(outp as *mut mig_reply_header_t);
        return;
    }
    let cred = begin_using_io((*inp).msgh_bits, (*inp).msgh_local_port);
    let _guard = ProtidGuard::new(cred);
    let reply = (*inp).msgh_remote_port;
    let reply_poly = mach_msgh_bits_remote((*inp).msgh_bits);
    let mut controlPoly: mach_msg_type_name_t = 0;
    (*outp).RetCode = trivfs_S_file_getcontrol(
        cred, reply, reply_poly, &mut (*outp).control, &mut controlPoly,
    );
    if (*outp).RetCode != KERN_SUCCESS { return; }
    (*outp).Head.msgh_size = size_of::<Reply_getcontrol>() as u32;
    let mut msgh_simple = true;
    (*outp).controlType = type_desc(controlPoly, MACH_PORT_INLINE_MSGT_SIZE, 1);
    if mach_msg_type_port_any_right(controlPoly) { msgh_simple = false; }
    if !msgh_simple { (*outp).Head.msgh_bits |= MACH_MSGH_BITS_COMPLEX; }
}

#[repr(C)]
struct Reply_getfh {
    Head: mach_msg_header_t,
    RetCodeType: mach_msg_type_t,
    RetCode: kern_return_t,
    filehandleType: mach_msg_type_long_t,
    filehandle: LongBuf2048,
} // size_of = 44 + 2048 = 2092; msgh_size wire = 44 + data_bytes (C:1801)

pub unsafe extern "C-unwind" fn _Xfile_getfh(
    inp: *mut mach_msg_header_t,
    outp: *mut Reply_getfh,
) {
    if (*inp).msgh_size != size_of::<mach_msg_header_t>() as u32
        || (*inp).msgh_bits & MACH_MSGH_BITS_COMPLEX != 0 {
        mig_bad_args(outp as *mut mig_reply_header_t);
        return;
    }
    let cred = begin_using_io((*inp).msgh_bits, (*inp).msgh_local_port);
    let _guard = ProtidGuard::new(cred);
    let reply = (*inp).msgh_remote_port;
    let reply_poly = mach_msgh_bits_remote((*inp).msgh_bits);
    let mut filehandleP: *mut c_char = (*outp).filehandle.inline.as_mut_ptr() as *mut c_char;
    let mut filehandleCnt: mach_msg_type_number_t = 2048;
    (*outp).RetCode = trivfs_S_file_getfh(
        cred, reply, reply_poly, &mut filehandleP, &mut filehandleCnt,
    );
    if (*outp).RetCode != KERN_SUCCESS { return; }

    let mut msgh_simple = true;
    if filehandleP != (*outp).filehandle.inline.as_mut_ptr() as *mut c_char {
        (*outp).filehandleType = type_desc_long_ool(MACH_MSG_TYPE_CHAR as u16, 8, filehandleCnt);
        (*outp).filehandle.ool = filehandleP;
        msgh_simple = false;
    } else {
        (*outp).filehandleType = type_desc_long(MACH_MSG_TYPE_CHAR as u16, 8, filehandleCnt);
    }
    let data_bytes = if msgh_simple { mach_msg_align(filehandleCnt as usize) } else { size_of::<*const c_char>() };
    (*outp).Head.msgh_size = (size_of::<Reply_getfh>() - 2048 + data_bytes) as u32;
    if !msgh_simple { (*outp).Head.msgh_bits |= MACH_MSGH_BITS_COMPLEX; }
}

#[repr(C)]
struct Reply_get_translator {
    Head: mach_msg_header_t,
    RetCodeType: mach_msg_type_t,
    RetCode: kern_return_t,
    translatorType: mach_msg_type_long_t,
    translator: LongBuf2048,
} // size_of = 44 + 2048 = 2092; msgh_size wire = 44 + data_bytes (C:3051)

pub unsafe extern "C-unwind" fn _Xfile_get_translator(
    inp: *mut mach_msg_header_t,
    outp: *mut Reply_get_translator,
) {
    if (*inp).msgh_size != size_of::<mach_msg_header_t>() as u32
        || (*inp).msgh_bits & MACH_MSGH_BITS_COMPLEX != 0 {
        mig_bad_args(outp as *mut mig_reply_header_t);
        return;
    }
    let cred = begin_using_io((*inp).msgh_bits, (*inp).msgh_local_port);
    let _guard = ProtidGuard::new(cred);
    let reply = (*inp).msgh_remote_port;
    let reply_poly = mach_msgh_bits_remote((*inp).msgh_bits);
    let mut translatorP: *mut c_char = (*outp).translator.inline.as_mut_ptr() as *mut c_char;
    let mut translatorCnt: mach_msg_type_number_t = 2048;
    (*outp).RetCode = trivfs_S_file_get_translator(
        cred, reply, reply_poly, &mut translatorP, &mut translatorCnt,
    );
    if (*outp).RetCode != KERN_SUCCESS { return; }

    let mut msgh_simple = true;
    if translatorP != (*outp).translator.inline.as_mut_ptr() as *mut c_char {
        (*outp).translatorType = type_desc_long_ool(MACH_MSG_TYPE_CHAR as u16, 8, translatorCnt);
        (*outp).translator.ool = translatorP;
        msgh_simple = false;
    } else {
        (*outp).translatorType = type_desc_long(MACH_MSG_TYPE_CHAR as u16, 8, translatorCnt);
    }
    let data_bytes = if msgh_simple { mach_msg_align(translatorCnt as usize) } else { size_of::<*const c_char>() };
    (*outp).Head.msgh_size = (size_of::<Reply_get_translator>() - 2048 + data_bytes) as u32;
    if !msgh_simple { (*outp).Head.msgh_bits |= MACH_MSGH_BITS_COMPLEX; }
}

#[repr(C)]
struct Reply_get_fs_options {
    Head: mach_msg_header_t,
    RetCodeType: mach_msg_type_t,
    RetCode: kern_return_t,
    optionsType: mach_msg_type_long_t,
    options: LongBuf2048,
} // size_of = 44 + 2048 = 2092; msgh_size wire = 44 + data_bytes (C:3230)

pub unsafe extern "C-unwind" fn _Xfile_get_fs_options(
    inp: *mut mach_msg_header_t,
    outp: *mut Reply_get_fs_options,
) {
    if (*inp).msgh_size != size_of::<mach_msg_header_t>() as u32
        || (*inp).msgh_bits & MACH_MSGH_BITS_COMPLEX != 0 {
        mig_bad_args(outp as *mut mig_reply_header_t);
        return;
    }
    let cred = begin_using_io((*inp).msgh_bits, (*inp).msgh_local_port);
    let _guard = ProtidGuard::new(cred);
    let reply = (*inp).msgh_remote_port;
    let reply_poly = mach_msgh_bits_remote((*inp).msgh_bits);
    let mut optionsP: *mut c_char = (*outp).options.inline.as_mut_ptr() as *mut c_char;
    let mut optionsCnt: mach_msg_type_number_t = 2048;
    (*outp).RetCode = trivfs_S_file_get_fs_options(
        cred, reply, reply_poly, &mut optionsP, &mut optionsCnt,
    );
    if (*outp).RetCode != KERN_SUCCESS { return; }

    let mut msgh_simple = true;
    if optionsP != (*outp).options.inline.as_mut_ptr() as *mut c_char {
        (*outp).optionsType = type_desc_long_ool(MACH_MSG_TYPE_CHAR as u16, 8, optionsCnt);
        (*outp).options.ool = optionsP;
        msgh_simple = false;
    } else {
        (*outp).optionsType = type_desc_long(MACH_MSG_TYPE_CHAR as u16, 8, optionsCnt);
    }
    let data_bytes = if msgh_simple { mach_msg_align(optionsCnt as usize) } else { size_of::<*const c_char>() };
    (*outp).Head.msgh_size = (size_of::<Reply_get_fs_options>() - 2048 + data_bytes) as u32;
    if !msgh_simple { (*outp).Head.msgh_bits |= MACH_MSGH_BITS_COMPLEX; }
}

#[repr(C)]
struct Req_dir_link {
    Head: mach_msg_header_t,
    fileType: mach_msg_type_t,
    file: mach_port_t,
    nameType: mach_msg_type_t,
    name: [c_char; 1024],
    exclType: mach_msg_type_t,
    excl: c_int,
} // 1068

pub unsafe extern "C-unwind" fn _Xdir_link(
    inp: *mut mach_msg_header_t,
    outp: *mut mig_reply_header_t,
) {
    let inp = inp as *const Req_dir_link;
    if (*inp).Head.msgh_size != size_of::<Req_dir_link>() as u32
        || (*inp).Head.msgh_bits & MACH_MSGH_BITS_COMPLEX == 0
    { mig_bad_args(outp); return; }
    if (*inp).fileType != T_PORT_SEND_1 { mig_bad_args(outp); return; }
    if (*inp).nameType != T_STRING_C_1024 { mig_bad_args(outp); return; }
    if (*inp).exclType != T_INTEGER_32_1 { mig_bad_args(outp); return; }

    let dir = begin_using_io((*inp).Head.msgh_bits, (*inp).Head.msgh_local_port);
    let _guard = ProtidGuard::new(dir);
    let reply = (*inp).Head.msgh_remote_port;
    let reply_poly = mach_msgh_bits_remote((*inp).Head.msgh_bits);
    let file = trivfs_begin_using_protid((*inp).file);
    let _guard = ProtidGuard::new(file);
    let name_ptr = (*inp).name.as_ptr() as *mut c_char;
    *name_ptr.add(1023) = 0;                     // C: In0P->name[1023] = '\0'
    (*outp).RetCode = trivfs_S_dir_link(dir, reply, reply_poly, file,
        name_ptr as *const c_char, (*inp).excl);
}

#[repr(C)]
struct Req_reparent {
    Head: mach_msg_header_t,
    parentType: mach_msg_type_t,
    parent: mach_port_t,
} // 32

#[repr(C)]
struct Reply_reparent {
    Head: mach_msg_header_t,
    RetCodeType: mach_msg_type_t,
    RetCode: kern_return_t,
    new_fileType: mach_msg_type_t,
    new_file: mach_port_t,
} // 40

pub unsafe extern "C-unwind" fn _Xfile_reparent(
    inp: *mut mach_msg_header_t,
    outp: *mut Reply_reparent,
) {
    let inp = inp as *const Req_reparent;
    if (*inp).Head.msgh_size != size_of::<Req_reparent>() as u32
        || (*inp).Head.msgh_bits & MACH_MSGH_BITS_COMPLEX == 0
    { mig_bad_args(outp as *mut mig_reply_header_t); return; }
    if (*inp).parentType != T_PORT_SEND_1 { mig_bad_args(outp as *mut mig_reply_header_t); return; }

    let file = begin_using_io((*inp).Head.msgh_bits, (*inp).Head.msgh_local_port);
    let _guard = ProtidGuard::new(file);
    let reply = (*inp).Head.msgh_remote_port;
    let reply_poly = mach_msgh_bits_remote((*inp).Head.msgh_bits);
    let mut new_filePoly: mach_msg_type_name_t = 0;
    (*outp).RetCode = trivfs_S_file_reparent(file, reply, reply_poly,
        (*inp).parent, &mut (*outp).new_file, &mut new_filePoly);
    if (*outp).RetCode != KERN_SUCCESS { return; }
    (*outp).Head.msgh_size = size_of::<Reply_reparent>() as u32;
    let mut msgh_simple = true;
    (*outp).new_fileType = type_desc(new_filePoly, MACH_PORT_INLINE_MSGT_SIZE, 1);
    if mach_msg_type_port_any_right(new_filePoly) { msgh_simple = false; }
    if !msgh_simple { (*outp).Head.msgh_bits |= MACH_MSGH_BITS_COMPLEX; }
}

#[repr(C)]
struct Req_record_lock {
    Head: mach_msg_header_t,
    cmdType: mach_msg_type_t,
    cmd: c_int,
    flock64Type: mach_msg_type_t,
    flock64: flock_t,
    rendezvousType: mach_msg_type_t,
    rendezvous: mach_port_t,
} // 72

#[repr(C)]
struct Reply_record_lock {
    Head: mach_msg_header_t,
    RetCodeType: mach_msg_type_t,
    RetCode: kern_return_t,
    flock64Type: mach_msg_type_t,
    flock64: flock_t,
} // 64

pub unsafe extern "C-unwind" fn _Xfile_record_lock(
    inp: *mut mach_msg_header_t,
    outp: *mut Reply_record_lock,
) {
    let inp = inp as *const Req_record_lock;
    if (*inp).Head.msgh_size != size_of::<Req_record_lock>() as u32
        || (*inp).Head.msgh_bits & MACH_MSGH_BITS_COMPLEX == 0
    { mig_bad_args(outp as *mut mig_reply_header_t); return; }
    if (*inp).cmdType != T_INTEGER_32_1 { mig_bad_args(outp as *mut mig_reply_header_t); return; }
    if (*inp).flock64Type != T_INTEGER_32_7 { mig_bad_args(outp as *mut mig_reply_header_t); return; }
    if (*inp).rendezvousType != T_PORT_SEND_1 { mig_bad_args(outp as *mut mig_reply_header_t); return; }

    let file = begin_using_io((*inp).Head.msgh_bits, (*inp).Head.msgh_local_port);
    let _guard = ProtidGuard::new(file);
    let reply = (*inp).Head.msgh_remote_port;
    let reply_poly = mach_msgh_bits_remote((*inp).Head.msgh_bits);
    (*outp).RetCode = trivfs_S_file_record_lock(file, reply, reply_poly,
        (*inp).cmd, (*inp).flock64.as_ptr() as *mut flock_t, (*inp).rendezvous);
    if (*outp).RetCode != KERN_SUCCESS { return; }
    (*outp).Head.msgh_size = size_of::<Reply_record_lock>() as u32;
    (*outp).flock64Type = T_INTEGER_32_7;
    (*outp).flock64 = (*inp).flock64;
}

#[repr(C)]
struct Req_exec {
    Head: mach_msg_header_t,
    exec_taskType: mach_msg_type_t,
    exec_task: mach_port_t,
    flagsType: mach_msg_type_t,
    flags: c_int,
    argvType: mach_msg_type_long_t,
} // 52

pub unsafe extern "C-unwind" fn _Xfile_exec(
    inp: *mut mach_msg_header_t,
    outp: *mut mig_reply_header_t,
) {
    let inp = inp as *const Req_exec;
    let msg = inp as *const u8;
    let base = size_of::<Req_exec>() + 6 * size_of::<mach_msg_type_long_t>();  // 124
    let msgh_size = (*inp).Head.msgh_size;
    if msgh_size < base as u32 || (*inp).Head.msgh_bits & MACH_MSGH_BITS_COMPLEX == 0
    { mig_bad_args(outp); return; }
    if (*inp).exec_taskType != T_PORT_SEND_1 { mig_bad_args(outp); return; }
    if (*inp).flagsType != T_INTEGER_32_1 { mig_bad_args(outp); return; }

    let pos = size_of::<Req_exec>();   // 52: start of argv data
    let mut run = 0u64;                    // accumulated deltas (equiv. to msgh_size -= delta in C)
    let char_ok = |t: &mach_msg_type_long_t, name: u16, size: u16| -> bool {
        t.is_longform() && t.name() == name && t.size() == size
    };
    let d_char = |t: &mach_msg_type_long_t| -> u64 {
        if t.is_inline() { ((t.number() as u64) + 3) & !3 } else { size_of::<*const c_char>() as u64 }
    };
    let d_word = |t: &mach_msg_type_long_t| -> u64 {
        if t.is_inline() { (t.number() as u64) * 4 } else { size_of::<*const c_void>() as u64 }
    };

    // argv (segment 1, in the struct)
    let a = (*inp).argvType;
    if !char_ok(&a, MACH_MSG_TYPE_CHAR as u16, 8) { mig_bad_args(outp); return; }
    let da = d_char(&a);
    if (msgh_size as u64) < (base as u64) + run + da { mig_bad_args(outp); return; }
    run += da;

    // envp (segment 2)
    let epos = pos + da as usize;
    let e = *(msg.add(epos) as *const mach_msg_type_long_t);
    if !char_ok(&e, MACH_MSG_TYPE_CHAR as u16, 8) { mig_bad_args(outp); return; }
    let de = d_char(&e);
    if (msgh_size as u64) < (base as u64) + run + de { mig_bad_args(outp); return; }
    run += de;

    // fdarray (segment 3): PORT_SEND, 32
    let fpos = epos + size_of::<mach_msg_type_long_t>() + de as usize;
    let f = *(msg.add(fpos) as *const mach_msg_type_long_t);
    if !char_ok(&f, MACH_MSG_TYPE_PORT_SEND as u16, 32) { mig_bad_args(outp); return; }
    let df = d_word(&f);
    if (msgh_size as u64) < (base as u64) + run + df { mig_bad_args(outp); return; }
    run += df;

    // portarray (segment 4): PORT_SEND, 32
    let gpos = fpos + size_of::<mach_msg_type_long_t>() + df as usize;
    let g = *(msg.add(gpos) as *const mach_msg_type_long_t);
    if !char_ok(&g, MACH_MSG_TYPE_PORT_SEND as u16, 32) { mig_bad_args(outp); return; }
    let dg = d_word(&g);
    if (msgh_size as u64) < (base as u64) + run + dg { mig_bad_args(outp); return; }
    run += dg;

    // intarray (segment 5): INTEGER_32, 32
    let ipos = gpos + size_of::<mach_msg_type_long_t>() + dg as usize;
    let it = *(msg.add(ipos) as *const mach_msg_type_long_t);
    if !char_ok(&it, MACH_MSG_TYPE_INTEGER_32 as u16, 32) { mig_bad_args(outp); return; }
    let di = d_word(&it);
    if (msgh_size as u64) < (base as u64) + run + di { mig_bad_args(outp); return; }
    run += di;

    // deallocnames (segment 6): PORT_NAME, 32
    let dpos = ipos + size_of::<mach_msg_type_long_t>() + di as usize;
    let dn = *(msg.add(dpos) as *const mach_msg_type_long_t);
    if !char_ok(&dn, MACH_MSG_TYPE_PORT_NAME as u16, 32) { mig_bad_args(outp); return; }
    let ddn = d_word(&dn);
    if (msgh_size as u64) < (base as u64) + run + ddn { mig_bad_args(outp); return; }
    run += ddn;

    // destroynames (segment 7): PORT_NAME, 32
    let tpos = dpos + size_of::<mach_msg_type_long_t>() + ddn as usize;
    let tn = *(msg.add(tpos) as *const mach_msg_type_long_t);
    if !char_ok(&tn, MACH_MSG_TYPE_PORT_NAME as u16, 32) { mig_bad_args(outp); return; }
    let dtn = d_word(&tn);
    if (msgh_size as u64) != (base as u64) + run + dtn { mig_bad_args(outp); return; }   // C: chequeo exacto final

    let exec_file = begin_using_io((*inp).Head.msgh_bits, (*inp).Head.msgh_local_port);
    let _guard = ProtidGuard::new(exec_file);
    let reply = (*inp).Head.msgh_remote_port;
    let reply_poly = mach_msgh_bits_remote((*inp).Head.msgh_bits);

    let a_data: *const c_char = if a.is_inline() { msg.add(pos) as *const c_char }
        else { *(msg.add(pos) as *const *const c_char) };
    let e_data: *const c_char = if e.is_inline() { msg.add(epos + size_of::<mach_msg_type_long_t>()) as *const c_char }
        else { *(msg.add(epos + size_of::<mach_msg_type_long_t>()) as *const *const c_char) };
    let f_data: *const mach_port_t = if f.is_inline() { msg.add(fpos + size_of::<mach_msg_type_long_t>()) as *const mach_port_t }
        else { *(msg.add(fpos + size_of::<mach_msg_type_long_t>()) as *const *const mach_port_t) };
    let g_data: *const mach_port_t = if g.is_inline() { msg.add(gpos + size_of::<mach_msg_type_long_t>()) as *const mach_port_t }
        else { *(msg.add(gpos + size_of::<mach_msg_type_long_t>()) as *const *const mach_port_t) };
    let it_data: *const c_int = if it.is_inline() { msg.add(ipos + size_of::<mach_msg_type_long_t>()) as *const c_int }
        else { *(msg.add(ipos + size_of::<mach_msg_type_long_t>()) as *const *const c_int) };
    let dn_data: *const mach_port_name_t = if dn.is_inline() { msg.add(dpos + size_of::<mach_msg_type_long_t>()) as *const mach_port_name_t }
        else { *(msg.add(dpos + size_of::<mach_msg_type_long_t>()) as *const *const mach_port_name_t) };
    let tn_data: *const mach_port_name_t = if tn.is_inline() { msg.add(tpos + size_of::<mach_msg_type_long_t>()) as *const mach_port_name_t }
        else { *(msg.add(tpos + size_of::<mach_msg_type_long_t>()) as *const *const mach_port_name_t) };

    (*outp).RetCode = trivfs_S_file_exec(exec_file, reply, reply_poly,
        (*inp).exec_task, (*inp).flags,
        a_data, a.number(), e_data, e.number(),
        f_data, f.number(), g_data, g.number(),
        it_data, it.number(), dn_data, dn.number(),
        tn_data, tn.number());

    if (*outp).RetCode == KERN_SUCCESS {
        if !tn.is_inline() { mig_deallocate(tn_data as vm_offset_t, (4 * tn.number()) as vm_size_t); }
        if !dn.is_inline() { mig_deallocate(dn_data as vm_offset_t, (4 * dn.number()) as vm_size_t); }
        if !it.is_inline() { mig_deallocate(it_data as vm_offset_t, (4 * it.number()) as vm_size_t); }
        if !g.is_inline() { mig_deallocate(g_data as vm_offset_t, (4 * g.number()) as vm_size_t); }
        if !f.is_inline() { mig_deallocate(f_data as vm_offset_t, (4 * f.number()) as vm_size_t); }
        if !e.is_inline() { mig_deallocate(e_data as vm_offset_t, e.number() as vm_size_t); }
        if !a.is_inline() { mig_deallocate(a_data as vm_offset_t, a.msgtl_number as vm_size_t); }
    }
}

#[repr(C)]
struct Req_chauthor {
    Head: mach_msg_header_t,
    new_authorType: mach_msg_type_t,
    new_author: u32,            // uid_t
} // 32

pub unsafe extern "C-unwind" fn _Xfile_chauthor(
    inp: *mut mach_msg_header_t,
    outp: *mut mig_reply_header_t,
) {
    let inp = inp as *const Req_chauthor;
    if (*inp).Head.msgh_size != size_of::<Req_chauthor>() as u32
        || (*inp).Head.msgh_bits & MACH_MSGH_BITS_COMPLEX != 0
    { mig_bad_args(outp); return; }
    if (*inp).new_authorType != T_INTEGER_32_1 { mig_bad_args(outp); return; }
    let cred = begin_using_io((*inp).Head.msgh_bits, (*inp).Head.msgh_local_port);
    let _guard = ProtidGuard::new(cred);
    let reply = (*inp).Head.msgh_remote_port;
    let reply_poly = mach_msgh_bits_remote((*inp).Head.msgh_bits);
    (*outp).RetCode = trivfs_S_file_chauthor(cred, reply, reply_poly, (*inp).new_author);
}

#[repr(C)]
struct Req_lock {
    Head: mach_msg_header_t,
    flagsType: mach_msg_type_t,
    flags: c_int,
} // 32

pub unsafe extern "C-unwind" fn _Xfile_lock(
    inp: *mut mach_msg_header_t,
    outp: *mut mig_reply_header_t,
) {
    let inp = inp as *const Req_lock;
    if (*inp).Head.msgh_size != size_of::<Req_lock>() as u32
        || (*inp).Head.msgh_bits & MACH_MSGH_BITS_COMPLEX != 0
    { mig_bad_args(outp); return; }
    if (*inp).flagsType != T_INTEGER_32_1 { mig_bad_args(outp); return; }
    let cred = begin_using_io((*inp).Head.msgh_bits, (*inp).Head.msgh_local_port);
    let _guard = ProtidGuard::new(cred);
    let reply = (*inp).Head.msgh_remote_port;
    let reply_poly = mach_msgh_bits_remote((*inp).Head.msgh_bits);
    (*outp).RetCode = trivfs_S_file_lock(cred, reply, reply_poly, (*inp).flags);
}

#[repr(C)]
struct Req_notice_changes {
    Head: mach_msg_header_t,
    portType: mach_msg_type_t,
    port: mach_port_t,
} // 32

pub unsafe extern "C-unwind" fn _Xfile_notice_changes(
    inp: *mut mach_msg_header_t,
    outp: *mut mig_reply_header_t,
) {
    let inp = inp as *const Req_notice_changes;
    if (*inp).Head.msgh_size != size_of::<Req_notice_changes>() as u32
        || (*inp).Head.msgh_bits & MACH_MSGH_BITS_COMPLEX == 0
    { mig_bad_args(outp); return; }
    if (*inp).portType != T_PORT_SEND_1 { mig_bad_args(outp); return; }
    let cred = begin_using_io((*inp).Head.msgh_bits, (*inp).Head.msgh_local_port);
    let _guard = ProtidGuard::new(cred);
    let reply = (*inp).Head.msgh_remote_port;
    let reply_poly = mach_msgh_bits_remote((*inp).Head.msgh_bits);
    (*outp).RetCode = trivfs_S_file_notice_changes(cred, reply, reply_poly, (*inp).port);
}

#[repr(C)]
struct Req_syncfs {
    Head: mach_msg_header_t,
    waitType: mach_msg_type_t,
    wait: c_int,
    do_childrenType: mach_msg_type_t,
    do_children: c_int,
} // 40

pub unsafe extern "C-unwind" fn _Xfile_syncfs(
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
    let cred = begin_using_io((*inp).Head.msgh_bits, (*inp).Head.msgh_local_port);
    let _guard = ProtidGuard::new(cred);
    let reply = (*inp).Head.msgh_remote_port;
    let reply_poly = mach_msgh_bits_remote((*inp).Head.msgh_bits);
    (*outp).RetCode = trivfs_S_file_syncfs(cred, reply, reply_poly, (*inp).wait, (*inp).do_children);
}

#[repr(C)]
struct Req_dir_notice_changes {
    Head: mach_msg_header_t,
    portType: mach_msg_type_t,
    port: mach_port_t,
} // 32

pub unsafe extern "C-unwind" fn _Xdir_notice_changes(
    inp: *mut mach_msg_header_t,
    outp: *mut mig_reply_header_t,
) {
    let inp = inp as *const Req_dir_notice_changes;
    if (*inp).Head.msgh_size != size_of::<Req_dir_notice_changes>() as u32
        || (*inp).Head.msgh_bits & MACH_MSGH_BITS_COMPLEX == 0
    { mig_bad_args(outp); return; }
    if (*inp).portType != T_PORT_SEND_1 { mig_bad_args(outp); return; }
    let cred = begin_using_io((*inp).Head.msgh_bits, (*inp).Head.msgh_local_port);
    let _guard = ProtidGuard::new(cred);
    let reply = (*inp).Head.msgh_remote_port;
    let reply_poly = mach_msgh_bits_remote((*inp).Head.msgh_bits);
    (*outp).RetCode = trivfs_S_dir_notice_changes(cred, reply, reply_poly, (*inp).port);
}

#[repr(C)]
struct Req_dir_lookup {
    Head: mach_msg_header_t,
    file_nameType: mach_msg_type_t,
    file_name: [c_char; 1024],
    flagsType: mach_msg_type_t,
    flags: c_int,
    modeType: mach_msg_type_t,
    mode: u32,                 // mode_t
} // 1068

#[repr(C)]
struct Reply_dir_lookup {
    Head: mach_msg_header_t,
    RetCodeType: mach_msg_type_t,
    RetCode: kern_return_t,
    do_retryType: mach_msg_type_t,
    do_retry: c_int,           // retry_type = int (C: _Static_assert 4*1)
    retry_nameType: mach_msg_type_t,
    retry_name: [c_char; 1024],
    resultType: mach_msg_type_t,
    result: mach_port_t,
} // 1076

pub unsafe extern "C-unwind" fn _Xdir_lookup(
    inp: *mut mach_msg_header_t,
    outp: *mut Reply_dir_lookup,
) {
    let inp = inp as *const Req_dir_lookup;
    if (*inp).Head.msgh_size != size_of::<Req_dir_lookup>() as u32
        || (*inp).Head.msgh_bits & MACH_MSGH_BITS_COMPLEX != 0
    { mig_bad_args(outp as *mut mig_reply_header_t); return; }
    if (*inp).file_nameType != T_STRING_C_1024 { mig_bad_args(outp as *mut mig_reply_header_t); return; }
    if (*inp).flagsType != T_INTEGER_32_1 { mig_bad_args(outp as *mut mig_reply_header_t); return; }
    if (*inp).modeType != T_INTEGER_32_1 { mig_bad_args(outp as *mut mig_reply_header_t); return; }

    let start_dir = begin_using_io((*inp).Head.msgh_bits, (*inp).Head.msgh_local_port);
    let _guard = ProtidGuard::new(start_dir);
    let reply = (*inp).Head.msgh_remote_port;
    let reply_poly = mach_msgh_bits_remote((*inp).Head.msgh_bits);
    let fn_ptr = (*inp).file_name.as_ptr() as *mut c_char;
    *fn_ptr.add(1023) = 0;                          // C: In0P->file_name[1023] = '\0'
    let mut resultPoly: mach_msg_type_name_t = 0;
    (*outp).RetCode = trivfs_S_dir_lookup(start_dir, reply, reply_poly,
        fn_ptr as *const c_char, (*inp).flags, (*inp).mode,
        &mut (*outp).do_retry, (*outp).retry_name.as_mut_ptr(),
        &mut (*outp).result, &mut resultPoly);
    if (*outp).RetCode != KERN_SUCCESS { return; }
    (*outp).Head.msgh_size = size_of::<Reply_dir_lookup>() as u32;
    let mut msgh_simple = true;
    (*outp).do_retryType = T_INTEGER_32_1;
    (*outp).retry_nameType = T_STRING_C_1024;
    (*outp).resultType = type_desc(resultPoly, MACH_PORT_INLINE_MSGT_SIZE, 1);
    if mach_msg_type_port_any_right(resultPoly) { msgh_simple = false; }
    if !msgh_simple { (*outp).Head.msgh_bits |= MACH_MSGH_BITS_COMPLEX; }
}

#[repr(C)]
struct Req_readdir {
    Head: mach_msg_header_t,
    entryType: mach_msg_type_t,
    entry: c_int,
    nentriesType: mach_msg_type_t,
    nentries: c_int,
    bufsizType: mach_msg_type_t,
    bufsiz: vm_size_t,           // 4 B i386
} // 48

#[repr(C)]
struct Reply_readdir {
    Head: mach_msg_header_t,
    RetCodeType: mach_msg_type_t,
    RetCode: kern_return_t,
    dataType: mach_msg_type_long_t,
    data: LongBuf2048,
} // base 44 + 2048 = 2092; wire msgh_size = 52 + delta (C:2141)

pub unsafe extern "C-unwind" fn _Xdir_readdir(
    inp: *mut mach_msg_header_t,
    outp: *mut Reply_readdir,
) {
    let inp = inp as *const Req_readdir;
    if (*inp).Head.msgh_size != size_of::<Req_readdir>() as u32
        || (*inp).Head.msgh_bits & MACH_MSGH_BITS_COMPLEX != 0
    { mig_bad_args(outp as *mut mig_reply_header_t); return; }
    if (*inp).entryType != T_INTEGER_32_1 { mig_bad_args(outp as *mut mig_reply_header_t); return; }
    if (*inp).nentriesType != T_INTEGER_32_1 { mig_bad_args(outp as *mut mig_reply_header_t); return; }
    if (*inp).bufsizType != T_INTEGER_32_1 { mig_bad_args(outp as *mut mig_reply_header_t); return; }

    let dir = begin_using_io((*inp).Head.msgh_bits, (*inp).Head.msgh_local_port);
    let _guard = ProtidGuard::new(dir);
    let reply = (*inp).Head.msgh_remote_port;
    let reply_poly = mach_msgh_bits_remote((*inp).Head.msgh_bits);
    let mut dataP: *mut c_char = (*outp).data.inline.as_mut_ptr() as *mut c_char;
    let mut dataCnt: mach_msg_type_number_t = 2048;
    let mut dataDealloc: boolean_t = 0;
    let mut amount: c_int = 0;
    (*outp).RetCode = trivfs_S_dir_readdir(dir, reply, reply_poly,
        &mut dataP, &mut dataCnt, &mut dataDealloc,
        (*inp).entry, (*inp).nentries, (*inp).bufsiz, &mut amount);
    if (*outp).RetCode != KERN_SUCCESS { return; }

    let mut msgh_simple = true;
    if dataP != (*outp).data.inline.as_mut_ptr() as *mut c_char {
        (*outp).dataType = if dataDealloc != 0 {
            type_desc_long_ool(MACH_MSG_TYPE_CHAR as u16, 8, dataCnt)
        } else {
            type_desc_long_ool_nodealloc(MACH_MSG_TYPE_CHAR as u16, 8, dataCnt)
        };
        (*outp).data.ool = dataP;
        msgh_simple = false;
    } else {
        (*outp).dataType = type_desc_long(MACH_MSG_TYPE_CHAR as u16, 8, dataCnt);
    }
    let delta = if msgh_simple { mach_msg_align(dataCnt as usize) } else { size_of::<*const c_char>() };
    (*outp).Head.msgh_size =
        (size_of::<Reply_readdir>() - 2048 + delta + size_of::<mach_msg_type_t>() + size_of::<c_int>()) as u32;
    let out_bytes = outp as *mut u8;
    let tail_off = size_of::<mach_msg_header_t>() + size_of::<mach_msg_type_t>()
        + size_of::<kern_return_t>() + size_of::<mach_msg_type_long_t>();   // 44 i386 / 52 amd64
    let tail = out_bytes.add(tail_off + delta);
    *(tail as *mut mach_msg_type_t) = T_INTEGER_32_1;                       // amountType
    *(tail.add(size_of::<mach_msg_type_t>()) as *mut c_int) = amount;       // amount
    if !msgh_simple { (*outp).Head.msgh_bits |= MACH_MSGH_BITS_COMPLEX; }
}

#[repr(C)]
struct Req_dir_mkfile {
    Head: mach_msg_header_t,
    flagsType: mach_msg_type_t,
    flags: c_int,
    modeType: mach_msg_type_t,
    mode: u32,                 // mode_t
} // 40

#[repr(C)]
struct Reply_dir_mkfile {
    Head: mach_msg_header_t,
    RetCodeType: mach_msg_type_t,
    RetCode: kern_return_t,
    newnodeType: mach_msg_type_t,
    newnode: mach_port_t,
} // 40

pub unsafe extern "C-unwind" fn _Xdir_mkfile(
    inp: *mut mach_msg_header_t,
    outp: *mut Reply_dir_mkfile,
) {
    let inp = inp as *const Req_dir_mkfile;
    if (*inp).Head.msgh_size != size_of::<Req_dir_mkfile>() as u32
        || (*inp).Head.msgh_bits & MACH_MSGH_BITS_COMPLEX != 0
    { mig_bad_args(outp as *mut mig_reply_header_t); return; }
    if (*inp).flagsType != T_INTEGER_32_1 { mig_bad_args(outp as *mut mig_reply_header_t); return; }
    if (*inp).modeType != T_INTEGER_32_1 { mig_bad_args(outp as *mut mig_reply_header_t); return; }

    let directory = begin_using_io((*inp).Head.msgh_bits, (*inp).Head.msgh_local_port);
    let _guard = ProtidGuard::new(directory);
    let reply = (*inp).Head.msgh_remote_port;
    let reply_poly = mach_msgh_bits_remote((*inp).Head.msgh_bits);
    let mut newnodePoly: mach_msg_type_name_t = 0;
    (*outp).RetCode = trivfs_S_dir_mkfile(directory, reply, reply_poly,
        (*inp).flags, (*inp).mode, &mut (*outp).newnode, &mut newnodePoly);
    if (*outp).RetCode != KERN_SUCCESS { return; }
    (*outp).Head.msgh_size = size_of::<Reply_dir_mkfile>() as u32;
    let mut msgh_simple = true;
    (*outp).newnodeType = type_desc(newnodePoly, MACH_PORT_INLINE_MSGT_SIZE, 1);
    if mach_msg_type_port_any_right(newnodePoly) { msgh_simple = false; }
    if !msgh_simple { (*outp).Head.msgh_bits |= MACH_MSGH_BITS_COMPLEX; }
}

#[repr(C)]
union PortBuf512 { inline: [mach_port_t; 512], ool: *mut mach_port_t }
#[repr(C)]
union IntBuf512 { inline: [c_int; 512], ool: *mut c_int }
#[repr(C)]
union OffBuf256 { inline: [loff_t; 256], ool: *mut loff_t }

#[repr(C)]
struct Reply_get_storage_info {
    Head: mach_msg_header_t,
    RetCodeType: mach_msg_type_t,
    RetCode: kern_return_t,
    portsType: mach_msg_type_long_t,
    ports: PortBuf512,
    intsType: mach_msg_type_long_t,
    ints: IntBuf512,
    offsetsType: mach_msg_type_long_t,
    offsets: OffBuf256,
    dataType: mach_msg_type_long_t,
    data: LongBuf2048,
} // 8272

pub unsafe extern "C-unwind" fn _Xfile_get_storage_info(
    inp: *mut mach_msg_header_t,
    outp: *mut Reply_get_storage_info,
) {
    if (*inp).msgh_size != size_of::<mach_msg_header_t>() as u32
        || (*inp).msgh_bits & MACH_MSGH_BITS_COMPLEX != 0 {
        mig_bad_args(outp as *mut mig_reply_header_t);
        return;
    }
    let file = begin_using_io((*inp).msgh_bits, (*inp).msgh_local_port);
    let _guard = ProtidGuard::new(file);
    let reply = (*inp).msgh_remote_port;
    let reply_poly = mach_msgh_bits_remote((*inp).msgh_bits);

    let mut portsP: *mut mach_port_t = (*outp).ports.inline.as_mut_ptr();
    let mut portsPoly: mach_msg_type_name_t = 0;
    let mut portsCnt: mach_msg_type_number_t = 512;
    let mut ints_local: [c_int; 512] = [0; 512];
    let mut intsP: *mut c_int = ints_local.as_mut_ptr();
    let mut intsCnt: mach_msg_type_number_t = 512;
    let mut offsets_local: [loff_t; 256] = [0; 256];
    let mut offsetsP: *mut loff_t = offsets_local.as_mut_ptr();
    let mut offsetsCnt: mach_msg_type_number_t = 256;
    let mut data_local: [u8; 2048] = [0; 2048];
    let mut dataP: *mut c_char = data_local.as_mut_ptr() as *mut c_char;
    let mut dataCnt: mach_msg_type_number_t = 2048;

    (*outp).RetCode = trivfs_S_file_get_storage_info(
        file, reply, reply_poly,
        &mut portsP, &mut portsPoly, &mut portsCnt,
        &mut intsP, &mut intsCnt,
        &mut offsetsP, &mut offsetsCnt,
        &mut dataP, &mut dataCnt,
    );
    if (*outp).RetCode != KERN_SUCCESS { return; }

    let out = outp as *mut u8;
    let mut msgh_simple = true;

    // ports (segment 1, in the struct)
    let ports_ool = portsP != (*outp).ports.inline.as_mut_ptr();
    (*outp).portsType = if ports_ool {
        type_desc_long_ool(portsPoly as u16, 32, portsCnt)
    } else {
        type_desc_long(portsPoly as u16, MACH_PORT_INLINE_MSGT_SIZE, portsCnt)
    };
    if ports_ool { (*outp).ports.ool = portsP; msgh_simple = false; }
    if mach_msg_type_port_any_right(portsPoly) { msgh_simple = false; }
    let dp = if ports_ool { size_of::<*const c_void>() } else { MACH_PORT_INLINE_SIZE * portsCnt as usize };
    let mut msgh_size = size_of::<mach_msg_header_t>() + size_of::<mach_msg_type_t>()
        + size_of::<kern_return_t>() + 4 * size_of::<mach_msg_type_long_t>() + dp;
    let mut pos = offset_of!(Reply_get_storage_info, ports) + dp;   // intsType wire (C: rebase OutP)

    // ints (segment 2): INTEGER_32, 32
    let ints_inline = intsP == ints_local.as_mut_ptr();
    *(out.add(pos) as *mut mach_msg_type_long_t) = if ints_inline {
        type_desc_long(MACH_MSG_TYPE_INTEGER_32 as u16, 32, intsCnt)
    } else {
        type_desc_long_ool(MACH_MSG_TYPE_INTEGER_32 as u16, 32, intsCnt)
    };
    if ints_inline {
        if intsCnt != 0 {
            std::ptr::copy_nonoverlapping(ints_local.as_ptr(),
                out.add(pos + size_of::<mach_msg_type_long_t>()) as *mut c_int, intsCnt as usize);
        }
    } else {
        *(out.add(pos + size_of::<mach_msg_type_long_t>()) as *mut *mut c_int) = intsP;
        msgh_simple = false;
    }
    let di = if ints_inline { (4 * intsCnt) as usize } else { size_of::<*const c_void>() };
    msgh_size += di;
    pos += size_of::<mach_msg_type_long_t>() + di;

    // offsets (segment 3): INTEGER_64, 64
    let offsets_inline = offsetsP == offsets_local.as_mut_ptr();
    *(out.add(pos) as *mut mach_msg_type_long_t) = if offsets_inline {
        type_desc_long(MACH_MSG_TYPE_INTEGER_64 as u16, 64, offsetsCnt)
    } else {
        type_desc_long_ool(MACH_MSG_TYPE_INTEGER_64 as u16, 64, offsetsCnt)
    };
    if offsets_inline {
        if offsetsCnt != 0 {
            std::ptr::copy_nonoverlapping(offsets_local.as_ptr(),
                out.add(pos + size_of::<mach_msg_type_long_t>()) as *mut loff_t, offsetsCnt as usize);
        }
    } else {
        *(out.add(pos + size_of::<mach_msg_type_long_t>()) as *mut *mut loff_t) = offsetsP;
        msgh_simple = false;
    }
    let do_ = if offsets_inline { (8 * offsetsCnt) as usize } else { size_of::<*const loff_t>() };
    msgh_size += do_;
    pos += size_of::<mach_msg_type_long_t>() + do_;

    // data (segment 4): CHAR, 8
    let data_inline = dataP == data_local.as_mut_ptr() as *mut c_char;
    *(out.add(pos) as *mut mach_msg_type_long_t) = if data_inline {
        type_desc_long(MACH_MSG_TYPE_CHAR as u16, 8, dataCnt)
    } else {
        type_desc_long_ool(MACH_MSG_TYPE_CHAR as u16, 8, dataCnt)
    };
    if data_inline {
        if dataCnt != 0 {
            std::ptr::copy_nonoverlapping(data_local.as_ptr(),
                out.add(pos + size_of::<mach_msg_type_long_t>()) as *mut u8, dataCnt as usize);
        }
    } else {
        *(out.add(pos + size_of::<mach_msg_type_long_t>()) as *mut *mut c_char) = dataP;
        msgh_simple = false;
    }
    let dd = if data_inline { mach_msg_align(dataCnt as usize) } else { size_of::<*const c_char>() };
    msgh_size += dd;

    (*outp).Head.msgh_size = msgh_size as u32;
    if !msgh_simple { (*outp).Head.msgh_bits |= MACH_MSGH_BITS_COMPLEX; }
}

#[repr(C)]
struct Req_dir_mkdir {
    Head: mach_msg_header_t,
    nameType: mach_msg_type_t,
    name: [c_char; 1024],
    modeType: mach_msg_type_t,
    mode: u32,             // mode_t
} // 1060

pub unsafe extern "C-unwind" fn _Xdir_mkdir(
    inp: *mut mach_msg_header_t,
    outp: *mut mig_reply_header_t,
) {
    let inp = inp as *const Req_dir_mkdir;
    if (*inp).Head.msgh_size != size_of::<Req_dir_mkdir>() as u32
        || (*inp).Head.msgh_bits & MACH_MSGH_BITS_COMPLEX != 0
    { mig_bad_args(outp); return; }
    if (*inp).nameType != T_STRING_C_1024 { mig_bad_args(outp); return; }
    if (*inp).modeType != T_INTEGER_32_1 { mig_bad_args(outp); return; }
    let directory = begin_using_io((*inp).Head.msgh_bits, (*inp).Head.msgh_local_port);
    let _guard = ProtidGuard::new(directory);
    let reply = (*inp).Head.msgh_remote_port;
    let reply_poly = mach_msgh_bits_remote((*inp).Head.msgh_bits);
    let name_ptr = (*inp).name.as_ptr() as *mut c_char;
    *name_ptr.add(1023) = 0;                          // C: In0P->name[1023] = '\0'
    (*outp).RetCode = trivfs_S_dir_mkdir(directory, reply, reply_poly,
        name_ptr as *const c_char, (*inp).mode);
}

#[repr(C)]
struct Req_dir_rmdir {
    Head: mach_msg_header_t,
    nameType: mach_msg_type_t,
    name: [c_char; 1024],
} // 1052

pub unsafe extern "C-unwind" fn _Xdir_rmdir(
    inp: *mut mach_msg_header_t,
    outp: *mut mig_reply_header_t,
) {
    let inp = inp as *const Req_dir_rmdir;
    if (*inp).Head.msgh_size != size_of::<Req_dir_rmdir>() as u32
        || (*inp).Head.msgh_bits & MACH_MSGH_BITS_COMPLEX != 0
    { mig_bad_args(outp); return; }
    if (*inp).nameType != T_STRING_C_1024 { mig_bad_args(outp); return; }
    let directory = begin_using_io((*inp).Head.msgh_bits, (*inp).Head.msgh_local_port);
    let _guard = ProtidGuard::new(directory);
    let reply = (*inp).Head.msgh_remote_port;
    let reply_poly = mach_msgh_bits_remote((*inp).Head.msgh_bits);
    let name_ptr = (*inp).name.as_ptr() as *mut c_char;
    *name_ptr.add(1023) = 0;                          // C: In0P->name[1023] = '\0'
    (*outp).RetCode = trivfs_S_dir_rmdir(directory, reply, reply_poly, name_ptr as *const c_char);
}

#[repr(C)]
struct Req_dir_rename {
    Head: mach_msg_header_t,
    oldnameType: mach_msg_type_t,
    oldname: [c_char; 1024],
    newdirectoryType: mach_msg_type_t,
    newdirectory: mach_port_t,
    newnameType: mach_msg_type_t,
    newname: [c_char; 1024],
    exclType: mach_msg_type_t,
    excl: c_int,
} // 2096

pub unsafe extern "C-unwind" fn _Xdir_rename(
    inp: *mut mach_msg_header_t,
    outp: *mut mig_reply_header_t,
) {
    let inp = inp as *const Req_dir_rename;
    if (*inp).Head.msgh_size != size_of::<Req_dir_rename>() as u32
        || (*inp).Head.msgh_bits & MACH_MSGH_BITS_COMPLEX == 0
    { mig_bad_args(outp); return; }
    if (*inp).oldnameType != T_STRING_C_1024 { mig_bad_args(outp); return; }
    if (*inp).newdirectoryType != T_PORT_SEND_1 { mig_bad_args(outp); return; }
    if (*inp).newnameType != T_STRING_C_1024 { mig_bad_args(outp); return; }
    if (*inp).exclType != T_INTEGER_32_1 { mig_bad_args(outp); return; }

    let olddirectory = begin_using_io((*inp).Head.msgh_bits, (*inp).Head.msgh_local_port);
    let _guard = ProtidGuard::new(olddirectory);
    let reply = (*inp).Head.msgh_remote_port;
    let reply_poly = mach_msgh_bits_remote((*inp).Head.msgh_bits);
    let oldname_ptr = (*inp).oldname.as_ptr() as *mut c_char;
    *oldname_ptr.add(1023) = 0;                       // C: oldname[1023] = '\0'
    let newdirectory = trivfs_begin_using_protid((*inp).newdirectory);
    let _guard = ProtidGuard::new(newdirectory);
    let newname_ptr = (*inp).newname.as_ptr() as *mut c_char;
    *newname_ptr.add(1023) = 0;                       // C: newname[1023] = '\0'
    (*outp).RetCode = trivfs_S_dir_rename(olddirectory, reply, reply_poly,
        oldname_ptr as *const c_char, newdirectory, newname_ptr as *const c_char, (*inp).excl);
}

pub unsafe extern "C-unwind" fn _Xdir_unlink(
    inp: *mut mach_msg_header_t,
    outp: *mut mig_reply_header_t,
) {
    let inp = inp as *const Req_dir_rmdir;
    if (*inp).Head.msgh_size != size_of::<Req_dir_rmdir>() as u32
        || (*inp).Head.msgh_bits & MACH_MSGH_BITS_COMPLEX != 0
    { mig_bad_args(outp); return; }
    if (*inp).nameType != T_STRING_C_1024 { mig_bad_args(outp); return; }
    let directory = begin_using_io((*inp).Head.msgh_bits, (*inp).Head.msgh_local_port);
    let _guard = ProtidGuard::new(directory);
    let reply = (*inp).Head.msgh_remote_port;
    let reply_poly = mach_msgh_bits_remote((*inp).Head.msgh_bits);
    let name_ptr = (*inp).name.as_ptr() as *mut c_char;
    *name_ptr.add(1023) = 0;                          // C: In0P->name[1023] = '\0'
    (*outp).RetCode = trivfs_S_dir_unlink(directory, reply, reply_poly, name_ptr as *const c_char);
}

#[repr(C)]
struct Req_set_translator {
    Head: mach_msg_header_t,
    passive_flagsType: mach_msg_type_t,
    passive_flags: c_int,
    active_flagsType: mach_msg_type_t,
    active_flags: c_int,
    oldtrans_flagsType: mach_msg_type_t,
    oldtrans_flags: c_int,
    passiveType: mach_msg_type_long_t,
    passive: LongBuf2048,
    activeType: mach_msg_type_t,
    active: mach_port_t,
} // base wire = size_of - 2048 (68 i386); activeType wire en offset_of - 2048 + delta

pub unsafe extern "C-unwind" fn _Xfile_set_translator(
    inp: *mut mach_msg_header_t,
    outp: *mut mig_reply_header_t,
) {
    let inp = inp as *const Req_set_translator;
    let msg = inp as *const u8;
    const ACTIVE_TYPE: usize = offset_of!(Req_set_translator, activeType) - 2048;
    let base = size_of::<Req_set_translator>() - 2048;
    if (*inp).Head.msgh_size < base as u32 || (*inp).Head.msgh_bits & MACH_MSGH_BITS_COMPLEX == 0
    { mig_bad_args(outp); return; }
    if (*inp).passive_flagsType != T_INTEGER_32_1 { mig_bad_args(outp); return; }
    if (*inp).active_flagsType != T_INTEGER_32_1 { mig_bad_args(outp); return; }
    if (*inp).oldtrans_flagsType != T_INTEGER_32_1 { mig_bad_args(outp); return; }
    let p = (*inp).passiveType;
    if !p.is_longform() || p.name() != MACH_MSG_TYPE_CHAR as u16 || p.size() != 8
    { mig_bad_args(outp); return; }
    let delta = if p.is_inline() { mach_msg_align(p.number() as usize) } else { size_of::<*const c_char>() };
    if (*inp).Head.msgh_size != base as u32 + delta as u32 { mig_bad_args(outp); return; }
    let active_type = *(msg.add(ACTIVE_TYPE + delta) as *const mach_msg_type_t);
    if active_type != T_PORT_SEND_1 { mig_bad_args(outp); return; }
    let active = *(msg.add(ACTIVE_TYPE + delta + size_of::<mach_msg_type_t>()) as *const mach_port_t);

    let file = begin_using_io((*inp).Head.msgh_bits, (*inp).Head.msgh_local_port);
    let _guard = ProtidGuard::new(file);
    let reply = (*inp).Head.msgh_remote_port;
    let reply_poly = mach_msgh_bits_remote((*inp).Head.msgh_bits);
    let passive = if p.is_inline() {
        (*inp).passive.inline.as_ptr() as *const c_char
    } else {
        (*inp).passive.ool
    };
    (*outp).RetCode = trivfs_S_file_set_translator(file, reply, reply_poly,
        (*inp).passive_flags, (*inp).active_flags, (*inp).oldtrans_flags,
        passive, p.number(), active);
    if (*outp).RetCode == KERN_SUCCESS && !p.is_inline() {
        mig_deallocate(passive as vm_offset_t, p.number() as vm_size_t);   // C: __mig_deallocate
    }
}

#[repr(C)]
struct Reply_get_translator_cntl {
    Head: mach_msg_header_t,
    RetCodeType: mach_msg_type_t,
    RetCode: kern_return_t,
    translator_cntlType: mach_msg_type_t,
    translator_cntl: mach_port_t,
} // 40

pub unsafe extern "C-unwind" fn _Xfile_get_translator_cntl(
    inp: *mut mach_msg_header_t,
    outp: *mut Reply_get_translator_cntl,
) {
    if (*inp).msgh_size != size_of::<mach_msg_header_t>() as u32
        || (*inp).msgh_bits & MACH_MSGH_BITS_COMPLEX != 0 {
        mig_bad_args(outp as *mut mig_reply_header_t);
        return;
    }
    let file = begin_using_io((*inp).msgh_bits, (*inp).msgh_local_port);
    let _guard = ProtidGuard::new(file);
    let reply = (*inp).msgh_remote_port;
    let reply_poly = mach_msgh_bits_remote((*inp).msgh_bits);
    let mut translator_cntlPoly: mach_msg_type_name_t = 0;
    (*outp).RetCode = trivfs_S_file_get_translator_cntl(
        file, reply, reply_poly, &mut (*outp).translator_cntl, &mut translator_cntlPoly);
    if (*outp).RetCode != KERN_SUCCESS { return; }
    (*outp).Head.msgh_size = size_of::<Reply_get_translator_cntl>() as u32;
    let mut msgh_simple = true;
    (*outp).translator_cntlType = type_desc(translator_cntlPoly, MACH_PORT_INLINE_MSGT_SIZE, 1);
    if mach_msg_type_port_any_right(translator_cntlPoly) { msgh_simple = false; }
    if !msgh_simple { (*outp).Head.msgh_bits |= MACH_MSGH_BITS_COMPLEX; }
}

#[repr(C)]
struct Req_utimens {
    Head: mach_msg_header_t,
    new_atimeType: mach_msg_type_t,
    new_atime: timespec_t,        // {tv_sec, tv_nsec}: 2×32 i386
    new_mtimeType: mach_msg_type_t,
    new_mtime: timespec_t,
} // 48

pub unsafe extern "C-unwind" fn _Xfile_utimens(
    inp: *mut mach_msg_header_t,
    outp: *mut mig_reply_header_t,
) {
    let inp = inp as *const Req_utimens;
    if (*inp).Head.msgh_size != size_of::<Req_utimens>() as u32
        || (*inp).Head.msgh_bits & MACH_MSGH_BITS_COMPLEX != 0
    { mig_bad_args(outp); return; }
    if (*inp).new_atimeType != T_TIMESPEC || (*inp).new_mtimeType != T_TIMESPEC {
        mig_bad_args(outp); return;
    }
    let cred = begin_using_io((*inp).Head.msgh_bits, (*inp).Head.msgh_local_port);
    let _guard = ProtidGuard::new(cred);
    let reply = (*inp).Head.msgh_remote_port;
    let reply_poly = mach_msgh_bits_remote((*inp).Head.msgh_bits);
    (*outp).RetCode = trivfs_S_file_utimens(cred, reply, reply_poly,
        (*inp).new_atime, (*inp).new_mtime);
}

#[repr(C)]
struct Req_exec_paths {
    Head: mach_msg_header_t,
    exec_taskType: mach_msg_type_t,
    exec_task: mach_port_t,
    flagsType: mach_msg_type_t,
    flags: c_int,
    pathType: mach_msg_type_t,
    path: [c_char; 1024],
    abspathType: mach_msg_type_t,
    abspath: [c_char; 1024],
    argvType: mach_msg_type_long_t,
} // 2108; base wire = 2108 + 6×12 = 2180

pub unsafe extern "C-unwind" fn _Xfile_exec_paths(
    inp: *mut mach_msg_header_t,
    outp: *mut mig_reply_header_t,
) {
    let inp = inp as *const Req_exec_paths;
    let msg = inp as *const u8;
    let base = size_of::<Req_exec_paths>() + 6 * size_of::<mach_msg_type_long_t>();  // 2180
    let msgh_size = (*inp).Head.msgh_size;
    if msgh_size < base as u32 || (*inp).Head.msgh_bits & MACH_MSGH_BITS_COMPLEX == 0
    { mig_bad_args(outp); return; }
    if (*inp).exec_taskType != T_PORT_SEND_1 { mig_bad_args(outp); return; }
    if (*inp).flagsType != T_INTEGER_32_1 { mig_bad_args(outp); return; }
    if (*inp).pathType != T_STRING_C_1024 { mig_bad_args(outp); return; }
    if (*inp).abspathType != T_STRING_C_1024 { mig_bad_args(outp); return; }

    let pos = size_of::<Req_exec_paths>();   // 2108: start of argv data
    let mut run = 0u64;                          // accumulated deltas (equiv. to msgh_size -= delta in C)
    let char_ok = |t: &mach_msg_type_long_t, name: u16, size: u16| -> bool {
        t.is_longform() && t.name() == name && t.size() == size
    };
    let d_char = |t: &mach_msg_type_long_t| -> u64 {
        if t.is_inline() { ((t.number() as u64) + 3) & !3 } else { size_of::<*const c_char>() as u64 }
    };
    let d_word = |t: &mach_msg_type_long_t| -> u64 {
        if t.is_inline() { (t.number() as u64) * 4 } else { size_of::<*const c_void>() as u64 }
    };

    // argv (segm. 1, in the struct): CHAR/8
    let a = (*inp).argvType;
    if !char_ok(&a, MACH_MSG_TYPE_CHAR as u16, 8) { mig_bad_args(outp); return; }
    let da = d_char(&a);
    if (msgh_size as u64) < (base as u64) + run + da { mig_bad_args(outp); return; }
    run += da;

    // envp (segm. 2): CHAR/8
    let epos = pos + da as usize;
    let e = *(msg.add(epos) as *const mach_msg_type_long_t);
    if !char_ok(&e, MACH_MSG_TYPE_CHAR as u16, 8) { mig_bad_args(outp); return; }
    let de = d_char(&e);
    if (msgh_size as u64) < (base as u64) + run + de { mig_bad_args(outp); return; }
    run += de;

    // fdarray (segm. 3): PORT_SEND/32
    let fpos = epos + size_of::<mach_msg_type_long_t>() + de as usize;
    let f = *(msg.add(fpos) as *const mach_msg_type_long_t);
    if !char_ok(&f, MACH_MSG_TYPE_PORT_SEND as u16, 32) { mig_bad_args(outp); return; }
    let df = d_word(&f);
    if (msgh_size as u64) < (base as u64) + run + df { mig_bad_args(outp); return; }
    run += df;

    // portarray (segm. 4): PORT_SEND/32
    let gpos = fpos + size_of::<mach_msg_type_long_t>() + df as usize;
    let g = *(msg.add(gpos) as *const mach_msg_type_long_t);
    if !char_ok(&g, MACH_MSG_TYPE_PORT_SEND as u16, 32) { mig_bad_args(outp); return; }
    let dg = d_word(&g);
    if (msgh_size as u64) < (base as u64) + run + dg { mig_bad_args(outp); return; }
    run += dg;

    // intarray (segm. 5): INTEGER_32/32
    let ipos = gpos + size_of::<mach_msg_type_long_t>() + dg as usize;
    let it = *(msg.add(ipos) as *const mach_msg_type_long_t);
    if !char_ok(&it, MACH_MSG_TYPE_INTEGER_32 as u16, 32) { mig_bad_args(outp); return; }
    let di = d_word(&it);
    if (msgh_size as u64) < (base as u64) + run + di { mig_bad_args(outp); return; }
    run += di;

    // deallocnames (segm. 6): PORT_NAME/32
    let dpos = ipos + size_of::<mach_msg_type_long_t>() + di as usize;
    let dn = *(msg.add(dpos) as *const mach_msg_type_long_t);
    if !char_ok(&dn, MACH_MSG_TYPE_PORT_NAME as u16, 32) { mig_bad_args(outp); return; }
    let ddn = d_word(&dn);
    if (msgh_size as u64) < (base as u64) + run + ddn { mig_bad_args(outp); return; }
    run += ddn;

    // destroynames (segm. 7): PORT_NAME/32 — chequeo EXACTO final (C:3557)
    let tpos = dpos + size_of::<mach_msg_type_long_t>() + ddn as usize;
    let tn = *(msg.add(tpos) as *const mach_msg_type_long_t);
    if !char_ok(&tn, MACH_MSG_TYPE_PORT_NAME as u16, 32) { mig_bad_args(outp); return; }
    let dtn = d_word(&tn);
    if (msgh_size as u64) != (base as u64) + run + dtn { mig_bad_args(outp); return; }

    let exec_file = begin_using_io((*inp).Head.msgh_bits, (*inp).Head.msgh_local_port);
    let _guard = ProtidGuard::new(exec_file);
    let reply = (*inp).Head.msgh_remote_port;
    let reply_poly = mach_msgh_bits_remote((*inp).Head.msgh_bits);

    // C:3598-3599: null-termination de path y abspath
    let path_ptr = (*inp).path.as_ptr() as *mut c_char;
    *path_ptr.add(1023) = 0;
    let abspath_ptr = (*inp).abspath.as_ptr() as *mut c_char;
    *abspath_ptr.add(1023) = 0;

    let a_data: *const c_char = if a.is_inline() { msg.add(pos) as *const c_char }
        else { *(msg.add(pos) as *const *const c_char) };
    let e_data: *const c_char = if e.is_inline() { msg.add(epos + size_of::<mach_msg_type_long_t>()) as *const c_char }
        else { *(msg.add(epos + size_of::<mach_msg_type_long_t>()) as *const *const c_char) };
    let f_data: *const mach_port_t = if f.is_inline() { msg.add(fpos + size_of::<mach_msg_type_long_t>()) as *const mach_port_t }
        else { *(msg.add(fpos + size_of::<mach_msg_type_long_t>()) as *const *const mach_port_t) };
    let g_data: *const mach_port_t = if g.is_inline() { msg.add(gpos + size_of::<mach_msg_type_long_t>()) as *const mach_port_t }
        else { *(msg.add(gpos + size_of::<mach_msg_type_long_t>()) as *const *const mach_port_t) };
    let it_data: *const c_int = if it.is_inline() { msg.add(ipos + size_of::<mach_msg_type_long_t>()) as *const c_int }
        else { *(msg.add(ipos + size_of::<mach_msg_type_long_t>()) as *const *const c_int) };
    let dn_data: *const mach_port_name_t = if dn.is_inline() { msg.add(dpos + size_of::<mach_msg_type_long_t>()) as *const mach_port_name_t }
        else { *(msg.add(dpos + size_of::<mach_msg_type_long_t>()) as *const *const mach_port_name_t) };
    let tn_data: *const mach_port_name_t = if tn.is_inline() { msg.add(tpos + size_of::<mach_msg_type_long_t>()) as *const mach_port_name_t }
        else { *(msg.add(tpos + size_of::<mach_msg_type_long_t>()) as *const *const mach_port_name_t) };

    (*outp).RetCode = trivfs_S_file_exec_paths(exec_file, reply, reply_poly,
        (*inp).exec_task, (*inp).flags,
        path_ptr as *const c_char, abspath_ptr as *const c_char,
        a_data, a.number(), e_data, e.number(),
        f_data, f.number(), g_data, g.number(),
        it_data, it.number(), dn_data, dn.number(),
        tn_data, tn.number());

    // Dealloc SOLO si KERN_SUCCESS, orden INVERSO (C:3603-3624)
    if (*outp).RetCode == KERN_SUCCESS {
        if !tn.is_inline() { mig_deallocate(tn_data as vm_offset_t, (4 * tn.number()) as vm_size_t); }
        if !dn.is_inline() { mig_deallocate(dn_data as vm_offset_t, (4 * dn.number()) as vm_size_t); }
        if !it.is_inline() { mig_deallocate(it_data as vm_offset_t, (4 * it.number()) as vm_size_t); }
        if !g.is_inline() { mig_deallocate(g_data as vm_offset_t, (4 * g.number()) as vm_size_t); }
        if !f.is_inline() { mig_deallocate(f_data as vm_offset_t, (4 * f.number()) as vm_size_t); }
        if !e.is_inline() { mig_deallocate(e_data as vm_offset_t, e.number() as vm_size_t); }
        if !a.is_inline() { mig_deallocate(a_data as vm_offset_t, a.number() as vm_size_t); }
    }
}

pub static trivfs_fs_server_routines: [Option<io_server_routine>; 37] = [
    Some(routine_cast(_Xfile_exec)),             // 20000
    Some(routine_cast(_Xfile_chown)),            // 20001
    Some(routine_cast(_Xfile_chauthor)),         // 20002
    Some(routine_cast(_Xfile_chmod)),            // 20003
    Some(routine_cast(_Xfile_chflags)),          // 20004
    Some(routine_cast(_Xfile_utimes)),           // 20005
    Some(routine_cast(_Xfile_set_size)),         // 20006
    Some(routine_cast(_Xfile_lock)),             // 20007
    Some(routine_cast(_Xfile_lock_stat)),        // 20008
    Some(routine_cast(_Xfile_check_access)),     // 20009
    Some(routine_cast(_Xfile_notice_changes)),   // 20010
    Some(routine_cast(_Xfile_getcontrol)),       // 20011
    Some(routine_cast(_Xfile_statfs)),           // 20012
    Some(routine_cast(_Xfile_sync)),             // 20013
    Some(routine_cast(_Xfile_syncfs)),           // 20014
    Some(routine_cast(_Xfile_get_storage_info)), // 20015
    Some(routine_cast(_Xfile_getlinknode)),      // 20016
    Some(routine_cast(_Xfile_getfh)),            // 20017
    Some(routine_cast(_Xdir_lookup)),            // 20018
    Some(routine_cast(_Xdir_readdir)),           // 20019
    Some(routine_cast(_Xdir_mkdir)),             // 20020
    Some(routine_cast(_Xdir_rmdir)),             // 20021
    Some(routine_cast(_Xdir_unlink)),            // 20022
    Some(routine_cast(_Xdir_link)),              // 20023
    Some(routine_cast(_Xdir_rename)),            // 20024
    Some(routine_cast(_Xdir_mkfile)),            // 20025
    Some(routine_cast(_Xdir_notice_changes)),    // 20026
    Some(routine_cast(_Xfile_set_translator)),   // 20027
    Some(routine_cast(_Xfile_get_translator)),   // 20028
    Some(routine_cast(_Xfile_get_translator_cntl)), // 20029
    Some(routine_cast(_Xfile_get_fs_options)),   // 20030
    Some(routine_cast(_Xfile_reparent)),         // 20031
    None,                                        // 20032 (NULL en C)
    None,                                        // 20033 (NULL en C)
    Some(routine_cast(_Xfile_exec_paths)),       // 20034
    Some(routine_cast(_Xfile_utimens)),          // 20035
    Some(routine_cast(_Xfile_record_lock)),      // 20036
];

#[unsafe(no_mangle)]
pub unsafe extern "C" fn trivfs_fs_server(
    InHeadP: *mut mach_msg_header_t,
    OutHeadP: *mut mach_msg_header_t,
) -> boolean_t {
    let OutP = OutHeadP as *mut mig_reply_header_t;
    mig_reply_header_setup(OutP, InHeadP);        // bits/size/remote/local=0/seqno/id+100/RetCodeType
    let id = (*InHeadP).msgh_id;
    if id > 20036 || id < 20000 {
        mig_bad_id(OutP);                          // C:3938
        return 0;
    }
    let Some(routine) = trivfs_fs_server_routines[(id - 20000) as usize] else {
        mig_bad_id(OutP);                          // slots 20032/20033 NULL → C:3940
        return 0;
    };
    let result = catch_unwind(AssertUnwindSafe(|| routine(InHeadP, OutHeadP)));
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