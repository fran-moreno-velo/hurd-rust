//===========================================================================//
// crate::gnuhurd::types                                                     //
//---------------------------------------------------------------------------//
// From github - gnuhurd                                                     //
// hurd/hurd/hurd_types.h                                                    //
// libshouldbeinlibc/refcount.h                                              //
//===========================================================================//

use std::ffi::{c_int, c_uint};
pub use libc::pthread_mutex_t;
pub use libc::pthread_cond_t;
pub use libc::pthread_spinlock_t;

use crate::gnumach::port::mach_port_t;

//---------------------------------------------------------------------------//
// Public types                                                              //
//---------------------------------------------------------------------------//

pub type refcount_t = c_uint;
pub type refcounts_t = _references;

#[repr(C)]
#[derive(Copy,Clone)]
pub struct references {
    pub hard: u32,
    pub weak: u32,
}

#[repr(C)]
#[derive(Copy,Clone)]
pub union _references {
    pub references: references,
    pub value: u64,
}

pub type fsys_t = mach_port_t;

//---------------------------------------------------------------------------//
// Public constants - File Systems                                           //
//---------------------------------------------------------------------------//

pub const FSTYPE_UFS     : u32 = 0x00000000; // 4.x BSD Fast File System
pub const FSTYPE_NFS     : u32 = 0x00000001; // Network File System ala Sun
pub const FSTYPE_GFS     : u32 = 0x00000002; // GNU file system
pub const FSTYPE_LFS     : u32 = 0x00000003; // Logging File System ala Sprite
pub const FSTYPE_SYSV    : u32 = 0x00000004; // Old U*x filesystem ala System V
pub const FSTYPE_FTP     : u32 = 0x00000005; // Transparent FTP
pub const FSTYPE_TAR     : u32 = 0x00000006; // Transparent TAR
pub const FSTYPE_AR      : u32 = 0x00000007; // Transparent AR
pub const FSTYPE_CPIO    : u32 = 0x00000008; // Transparent CPIO
pub const FSTYPE_MSLOSS  : u32 = 0x00000009; // MS-DOS
pub const FSTYPE_CPM     : u32 = 0x0000000a; // CP/M
pub const FSTYPE_HFS     : u32 = 0x0000000b; // Don't ask
pub const FSTYPE_DTFS    : u32 = 0x0000000c; // used by desktop to provide more info
pub const FSTYPE_GRFS    : u32 = 0x0000000d; // GNU Remote File System
pub const FSTYPE_TERM    : u32 = 0x0000000e; // GNU Terminal driver
pub const FSTYPE_DEV     : u32 = 0x0000000f; // GNU Special file server
pub const FSTYPE_PROC    : u32 = 0x00000010; // /proc filesystem ala Version 9
pub const FSTYPE_IFSOCK  : u32 = 0x00000011; // PF_LOCAL socket naming point
pub const FSTYPE_AFS     : u32 = 0x00000012; // Andrew File System 3.xx
pub const FSTYPE_DFS     : u32 = 0x00000013; // Distributed File Sys (OSF) == AFS 4.xx
pub const FSTYPE_PROC9   : u32 = 0x00000014; // /proc filesystem ala Plan 9
pub const FSTYPE_SOCKET  : u32 = 0x00000015; // io_t that isn't a file but a socket
pub const FSTYPE_MISC    : u32 = 0x00000016; // generic trivfs server
pub const FSTYPE_EXT2FS  : u32 = 0x00000017; // Linux filesystem by Remy Card
pub const FSTYPE_HTTP    : u32 = 0x00000018; // Transparent HTTP
pub const FSTYPE_MEMFS   : u32 = 0x00000019; // In-core filesystem
pub const FSTYPE_ISO9660 : u32 = 0x0000001a; // ISO9660
pub const FSTYPE_PCI     : u32 = 0x0000001b; // PCI filesystem
pub const FSTYPE_ACPI    : u32 = 0x0000001c; // ACPI filesystem

pub const FS_TRANS_SET: u32 = 4;
pub const FS_RETRY_NORMAL: retry_type = 1;
pub const FS_RETRY_REAUTH: retry_type = 2;
pub const FS_RETRY_MAGICAL: retry_type = 3;

pub type retry_type = c_int;