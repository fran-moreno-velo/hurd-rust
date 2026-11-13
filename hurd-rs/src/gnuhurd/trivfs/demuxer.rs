//===========================================================================//
// crate::hurd::trivfs                                                       //
//---------------------------------------------------------------------------//
// From github - gnuhurd                                                     //
// /hurd/libtrivfs/trivfs.h                                                  //
//===========================================================================//

// Import types

use crate::gnumach::message::mach_msg_header_t;
use crate::gnumach::message::mach_msg_id_t;
use crate::gnumach::mig::mig_routine_t;
use crate::gnuhurd::ports::{
    ports_manage_port_operations_one_thread, ports_manage_port_operations_multithread,
    ports_demuxer_t,
};
use crate::gnuhurd::trivfs::types::trivfs_control_t;
use crate::gnuhurd::trivfs::hooks::Hook;
use crate::gnuhurd::trivfs::io_server::trivfs_io_server;
use crate::gnuhurd::trivfs::fs_server::trivfs_fs_server;
use crate::gnuhurd::trivfs::fsys_server::trivfs_fsys_server;

use std::ffi::c_int;
use std::panic::{catch_unwind, AssertUnwindSafe};

// Import functions
use crate::gnuhurd::ports::{ports_interrupt_server_routine, ports_notify_server_routine};

//---------------------------------------------------------------------------//
// Demuxer hook types                                                        //
//---------------------------------------------------------------------------//

pub type DemuxerFn = unsafe extern "C-unwind" fn(
    inp: *mut mach_msg_header_t,
    outp: *mut mach_msg_header_t,
) -> c_int;

static DEMUXER_HOOK: Hook<DemuxerFn> = Hook::new();

pub fn register_demuxer(f: DemuxerFn) { let _ = DEMUXER_HOOK.set(f); }

//---------------------------------------------------------------------------//
// Panic hook conciso                                                         //
//---------------------------------------------------------------------------//

/// Installs a panic hook that prints only the message + location (without the
/// ~50-frame backtrace the default prints with RUST_BACKTRACE=full).
///
/// It is installed from `trivfs_startup`, so all translators inherit it.
/// For deep diagnostics, setting `HURD_RPC_PANIC_BACKTRACE=1` (or `full`)
/// prints the full backtrace.
pub fn install_concise_panic_hook() {
    std::panic::set_hook(Box::new(|info| {
        let thread = std::thread::current();
        let name = thread.name().unwrap_or("<unnamed>");
        let loc = info.location()
            .map(|l| format!("{}:{}", l.file(), l.line()))
            .unwrap_or_else(|| "?".into());
        let msg = panic_message(info.payload());
        eprintln!("thread '{name}' panicked at {loc}:\n{msg}");
        let full = std::env::var_os("HURD_RPC_PANIC_BACKTRACE")
            .map_or(false, |v| v == "1" || v == "full");
        if full {
            let bt = std::backtrace::Backtrace::force_capture();
            eprintln!("{bt}");
        }
    }));
}

fn panic_message(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(s) = payload.downcast_ref::<&str>() {
        (*s).to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "Box<dyn Any>".to_string()
    }
}

//---------------------------------------------------------------------------//
// Demuxer functions                                                         //
//---------------------------------------------------------------------------//

pub const TRIVFS_IO_MSGH_BASE: mach_msg_id_t = 21000;
pub const TRIVFS_IO_MSGH_COUNT: mach_msg_id_t = 32;
pub const TRIVFS_FS_MSGH_BASE: mach_msg_id_t = 20000;
pub const TRIVFS_FS_MSGH_COUNT: mach_msg_id_t = 37;
pub const TRIVFS_FSYS_MSGH_BASE: mach_msg_id_t = 22000;
pub const TRIVFS_FSYS_MSGH_COUNT: mach_msg_id_t = 12;

#[unsafe(no_mangle)]
pub unsafe extern "C" fn trivfs_demuxer(
      inp:  *mut mach_msg_header_t,
      outp: *mut mach_msg_header_t
  ) -> c_int
{
    match DEMUXER_HOOK.get() {
        Some(f) => {
            // The custom demuxer is `extern "C-unwind"`, but `trivfs_demuxer`
            // is `extern "C"` (interop with libports): if the hook panics, the
            // unwind cannot cross the `extern "C"` frame → abort. We catch it
            // here (inside the frame) and return 0 (equivalent to MIG_BAD_ID).
            catch_unwind(AssertUnwindSafe(|| unsafe { f(inp, outp) })).unwrap_or_else(|p| {
                let msg = p.downcast_ref::<&str>().map(|s| s.to_string())
                    .or_else(|| p.downcast_ref::<String>().cloned())
                    .unwrap_or_else(|| "unknown panic".into());
                eprintln!("[hurd-rs] custom demuxer panicked, ignoring message: {msg}");
                0
            })
        }
        None => trivfs_demuxer_builtin(inp, outp),
    }
}

/// trivfs builtin dispatch (io/fs/fsys/ports/notify/interrupt servers),
/// without consulting `DEMUXER_HOOK`. Custom demuxers that want to delegate
/// non-own messages MUST call this function (calling `trivfs_demuxer`
/// recurses: it would invoke the hook again).
pub unsafe fn trivfs_demuxer_builtin(
    inp: *mut mach_msg_header_t,
    outp: *mut mach_msg_header_t,
) -> c_int {
    let Some(routine) = trivfs_io_server_routine(inp)
        .or_else(|| trivfs_fs_server_routine(inp))
        .or_else(|| ports_notify_server_routine(inp))
        .or_else(|| trivfs_fsys_server_routine(inp))
        .or_else(|| ports_interrupt_server_routine(inp))
    else { return 0; };
    unsafe { routine(inp, outp) };
    1
}

pub fn trivfs_io_server_routine(inp: *mut mach_msg_header_t) -> mig_routine_t
{
  let inp = match unsafe { inp.as_ref() } {
    Some(h) => h,
    None => return None,
  };
  let msgh_base = TRIVFS_IO_MSGH_BASE;
  let msgh_limit = TRIVFS_IO_MSGH_BASE + TRIVFS_IO_MSGH_COUNT;
  if inp.msgh_id >= msgh_base && inp.msgh_id < msgh_limit { Some(trivfs_io_server) }
  else { None }
}

pub fn trivfs_fs_server_routine(inp: *mut mach_msg_header_t) -> mig_routine_t
{
  let inp = match unsafe { inp.as_ref() } {
    Some(h) => h,
    None => return None,
  };
  let msgh_base = TRIVFS_FS_MSGH_BASE;
  let msgh_limit = TRIVFS_FS_MSGH_BASE + TRIVFS_FS_MSGH_COUNT;
  if inp.msgh_id >= msgh_base && inp.msgh_id < msgh_limit { Some(trivfs_fs_server) }
  else { None }
}

pub fn trivfs_fsys_server_routine(inp: *mut mach_msg_header_t) -> mig_routine_t
{
  let inp = match unsafe { inp.as_ref() } {
    Some(h) => h,
    None => return None,
  };
  let msgh_base = TRIVFS_FSYS_MSGH_BASE;
  let msgh_limit = TRIVFS_FSYS_MSGH_BASE + TRIVFS_FSYS_MSGH_COUNT;
  if inp.msgh_id >= msgh_base && inp.msgh_id < msgh_limit { Some(trivfs_fsys_server) }
  else { None }
}

//---------------------------------------------------------------------------//
// Wrappers                                                        //
//---------------------------------------------------------------------------//

pub fn run_demuxer(
    cntl: &mut trivfs_control_t,
    demuxer: ports_demuxer_t,
    timeout: c_int,
) {
    unsafe { ports_manage_port_operations_one_thread(cntl.pi.bucket, demuxer, timeout) }
}

/// run_demuxer_mt: same as run_demuxer but serves requests on multiple
/// threads (C: ports_manage_port_operations_multithread). Useful for
/// translators whose RPC handlers may block (e.g. network filesystems);
/// single-threaded demuxing would stall all other requests meanwhile.
pub fn run_demuxer_mt(
    cntl: &mut trivfs_control_t,
    demuxer: ports_demuxer_t,
    thread_timeout: c_int,
    global_timeout: c_int,
    hook: Option<unsafe extern "C" fn()>,
) {
    unsafe { ports_manage_port_operations_multithread(cntl.pi.bucket, demuxer, thread_timeout, global_timeout, hook) }
}