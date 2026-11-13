pub mod ioctl;
pub mod startup;
pub mod demuxer;
pub mod control;
pub mod fsys_server;
pub mod types;
pub mod dynamic;
pub mod source;
pub mod append;
pub mod make;
pub mod set_options;
pub mod dir;
pub mod file;
pub mod times;
pub mod protid;
#[path = "trivfs/priv.rs"]
pub mod private;
pub mod open;
pub mod io_handlers;
pub mod io_stubs;
pub mod fsys_stubs;
pub mod hooks;
pub mod symbols;

#[allow(dead_code)]
pub mod mig_helpers;

#[allow(dead_code)]
pub mod io_server;
pub mod fs_server;


#[cfg(test)]
mod test_abi_syms {
    use std::ffi::c_int;

    #[unsafe(no_mangle)] pub static mut trivfs_fstype: c_int = 0;
    #[unsafe(no_mangle)] pub static mut trivfs_fsid: c_int = 0;
    #[unsafe(no_mangle)] pub static mut trivfs_allow_open: c_int = 0;
    #[unsafe(no_mangle)] pub static mut trivfs_support_read: c_int = 1;
    #[unsafe(no_mangle)] pub static mut trivfs_support_write: c_int = 1;
    #[unsafe(no_mangle)] pub static mut trivfs_support_exec: c_int = 0;
}