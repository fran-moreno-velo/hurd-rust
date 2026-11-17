//===========================================================================//
// crate::gnuhurd::process                                                   //
//---------------------------------------------------------------------------//
// From hurd/process.defs (subsystem process 24000) - stubs de cliente       //
// (libhurduser) y getproc() de glibc <hurd.h>                               //
//===========================================================================//
// Ver las convenciones de MIG en auth.rs.  "out pidarray_t, dealloc" es
// (pid_t **, Cnt *) con la regla habitual de memoria fuera de línea.

use libc::{pid_t, uid_t};
use std::ffi::{c_char, c_int};
use crate::gnuhurd::io::data_t;
use crate::gnuhurd::types::{const_string_t, process_t, procinfo_t, rusage_t};
use crate::gnumach::boolean::boolean_t;
use crate::gnumach::device::device_t;
use crate::gnumach::kern_return::kern_return_t;
use crate::gnumach::mach_types::{host_priv_t, task_t, thread_t};
use crate::gnumach::message::{mach_msg_type_name_t, mach_msg_type_number_t};
use crate::gnumach::port::mach_port_t;
use crate::gnumach::thread::thread_state_t;
use crate::gnumach::vm_types::vm_address_t;

unsafe extern "C" {
    /// glibc <hurd.h>: puerto del servidor de procesos para este proceso
    /// (referencia nueva: liberarla con mach_port_deallocate).
    pub fn getproc() -> process_t;
}

#[link(name = "hurduser")]
unsafe extern "C" {
    // --- Host management ---
    pub fn proc_getprivports(process: process_t, host_priv: *mut host_priv_t,
                             device_master: *mut device_t) -> kern_return_t;
    pub fn proc_getallpids(process: process_t, pidarray: *mut *mut pid_t,
                           pidarray_cnt: *mut mach_msg_type_number_t) -> kern_return_t;
    pub fn proc_setexecdata(process: process_t,
                            ports: *mut mach_port_t, ports_poly: mach_msg_type_name_t,
                            ports_cnt: mach_msg_type_number_t,
                            ints: *const c_int, ints_cnt: mach_msg_type_number_t)
        -> kern_return_t;
    pub fn proc_getexecdata(process: process_t,
                            ports: *mut *mut mach_port_t, ports_cnt: *mut mach_msg_type_number_t,
                            ints: *mut *mut c_int, ints_cnt: *mut mach_msg_type_number_t)
        -> kern_return_t;
    pub fn proc_execdata_notify(process: process_t, notify: mach_port_t,
                                notify_poly: mach_msg_type_name_t) -> kern_return_t;
    /// VERIFICAR: utsname_t de hurd_types.defs frente a libc::utsname.
    pub fn proc_uname(process: process_t, uname: *mut libc::utsname) -> kern_return_t;
    pub fn proc_register_version(process: process_t, credential: host_priv_t,
                                 name: const_string_t, release: const_string_t,
                                 version: const_string_t) -> kern_return_t;

    // --- Process creation and simple management ---
    pub fn proc_reauthenticate(process: process_t, rendezvous: mach_port_t,
                               rendezvous_poly: mach_msg_type_name_t) -> kern_return_t;
    pub fn proc_child(process: process_t, child: task_t) -> kern_return_t;
    pub fn proc_setmsgport(process: process_t, newmsgport: mach_port_t,
                           oldmsgport: *mut mach_port_t) -> kern_return_t;
    pub fn proc_reassign(process: process_t, newtask: task_t) -> kern_return_t;
    /// Obsoleta.
    pub fn proc_setowner(process: process_t, owner: uid_t, clear: c_int) -> kern_return_t;
    pub fn proc_getpids(process: process_t, pid: *mut pid_t, ppid: *mut pid_t,
                        orphaned: *mut c_int) -> kern_return_t;
    pub fn proc_set_arg_locations(process: process_t, argv: vm_address_t,
                                  envp: vm_address_t) -> kern_return_t;
    pub fn proc_get_arg_locations(process: process_t, argv: *mut vm_address_t,
                                  envp: *mut vm_address_t) -> kern_return_t;
    pub fn proc_getmsgport(process: process_t, pid: pid_t,
                           msgport: *mut mach_port_t) -> kern_return_t;
    pub fn proc_wait(process: process_t, pid: pid_t, options: c_int,
                     status: *mut c_int, sigcode: *mut c_int, rusage: *mut rusage_t,
                     pid_status: *mut pid_t) -> kern_return_t;
    pub fn proc_dostop(process: process_t, contthread: thread_t) -> kern_return_t;
    pub fn proc_handle_exceptions(process: process_t, msgport: mach_port_t,
                                  forwardport: mach_port_t,
                                  forwardport_poly: mach_msg_type_name_t,
                                  flavor: c_int, new_state: thread_state_t,
                                  new_state_cnt: mach_msg_type_number_t) -> kern_return_t;

    // --- Mark bits ---
    pub fn proc_mark_stop(process: process_t, signo: c_int, sigcode: c_int) -> kern_return_t;
    pub fn proc_mark_cont(process: process_t) -> kern_return_t;
    pub fn proc_mark_exit(process: process_t, status: c_int, sigcode: c_int) -> kern_return_t;
    pub fn proc_mark_exec(process: process_t) -> kern_return_t;
    pub fn proc_mark_traced(process: process_t) -> kern_return_t;
    pub fn proc_mod_stopchild(process: process_t, doit: c_int) -> kern_return_t;

    // --- Miscellaneous process information queries ---
    /// *task recibe un derecho de envío nuevo.
    pub fn proc_pid2task(process: process_t, pid: pid_t, task: *mut task_t) -> kern_return_t;
    pub fn proc_task2pid(process: process_t, task: task_t, pid: *mut pid_t) -> kern_return_t;
    pub fn proc_task2proc(process: process_t, task: task_t,
                          proc_: *mut mach_port_t) -> kern_return_t;
    pub fn proc_proc2task(process: process_t, task: *mut task_t) -> kern_return_t;
    pub fn proc_pid2proc(process: process_t, pid: pid_t,
                         proc_: *mut mach_port_t) -> kern_return_t;
    pub fn proc_getprocinfo(process: process_t, which: pid_t, flags: *mut c_int,
                            procinfo: *mut procinfo_t, procinfo_cnt: *mut mach_msg_type_number_t,
                            threadwaits: *mut data_t, threadwaits_cnt: *mut mach_msg_type_number_t)
        -> kern_return_t;
    pub fn proc_getprocargs(process: process_t, which: pid_t, procargs: *mut data_t,
                            procargs_cnt: *mut mach_msg_type_number_t) -> kern_return_t;
    pub fn proc_getprocenv(process: process_t, which: pid_t, procenv: *mut data_t,
                           procenv_cnt: *mut mach_msg_type_number_t) -> kern_return_t;
    pub fn proc_make_login_coll(process: process_t) -> kern_return_t;
    pub fn proc_getloginid(process: process_t, pid: pid_t, login_id: *mut pid_t) -> kern_return_t;
    pub fn proc_getloginpids(process: process_t, id: pid_t, pids: *mut *mut pid_t,
                             pids_cnt: *mut mach_msg_type_number_t) -> kern_return_t;
    pub fn proc_setlogin(process: process_t, logname: const_string_t) -> kern_return_t;
    /// `logname` debe apuntar a un buffer de STRING_T_SIZE bytes.
    pub fn proc_getlogin(process: process_t, logname: *mut c_char) -> kern_return_t;

    // --- Sessions and process groups ---
    pub fn proc_setsid(process: process_t) -> kern_return_t;
    pub fn proc_getsid(process: process_t, pid: pid_t, sid: *mut pid_t) -> kern_return_t;
    pub fn proc_getsessionpgids(process: process_t, sid: pid_t, pgidset: *mut *mut pid_t,
                                pgidset_cnt: *mut mach_msg_type_number_t) -> kern_return_t;
    pub fn proc_getsessionpids(process: process_t, sid: pid_t, pidset: *mut *mut pid_t,
                               pidset_cnt: *mut mach_msg_type_number_t) -> kern_return_t;
    pub fn proc_getsidport(process: process_t, sessport: *mut mach_port_t) -> kern_return_t;
    pub fn proc_setpgrp(process: process_t, pid: pid_t, pgrp: pid_t) -> kern_return_t;
    pub fn proc_getpgrp(process: process_t, pid: pid_t, pgrp: *mut pid_t) -> kern_return_t;
    pub fn proc_getpgrppids(process: process_t, pgrp: pid_t, pidset: *mut *mut pid_t,
                            pidset_cnt: *mut mach_msg_type_number_t) -> kern_return_t;

    // --- Other miscellaneous info queries ---
    pub fn proc_get_tty(calling_process: process_t, target_process: pid_t,
                        tty: *mut mach_port_t) -> kern_return_t;
    pub fn proc_getnports(process: process_t, which: pid_t,
                          nports: *mut mach_msg_type_number_t) -> kern_return_t;

    // --- Early server bootstrapping ---
    pub fn proc_set_init_task(process: process_t, task: task_t) -> kern_return_t;
    pub fn proc_mark_important(process: process_t) -> kern_return_t;
    pub fn proc_is_important(process: process_t, essential: *mut boolean_t) -> kern_return_t;
    pub fn proc_set_code(process: process_t, start_code: vm_address_t,
                         end_code: vm_address_t) -> kern_return_t;
    pub fn proc_get_code(process: process_t, start_code: *mut vm_address_t,
                         end_code: *mut vm_address_t) -> kern_return_t;
    pub fn proc_make_task_namespace(process: process_t, notify: mach_port_t,
                                    notify_poly: mach_msg_type_name_t) -> kern_return_t;
    pub fn proc_set_exe(process: process_t, path: const_string_t) -> kern_return_t;
    /// `path` debe apuntar a un buffer de STRING_T_SIZE bytes.
    pub fn proc_get_exe(process: process_t, which: pid_t, path: *mut c_char) -> kern_return_t;
    pub fn proc_set_entry(process: process_t, entry: vm_address_t) -> kern_return_t;
    pub fn proc_get_entry(process: process_t, entry: *mut vm_address_t) -> kern_return_t;
    pub fn proc_waitid(process: process_t, pid: pid_t, options: c_int,
                       status: *mut c_int, sigcode: *mut c_int, rusage: *mut rusage_t,
                       pid_status: *mut pid_t) -> kern_return_t;
    pub fn proc_reauthenticate_reassign(old_process: process_t, rendezvous: mach_port_t,
                                        rendezvous_poly: mach_msg_type_name_t,
                                        new_task: task_t) -> kern_return_t;
    pub fn proc_reauthenticate_complete(process: process_t) -> kern_return_t;
    pub fn proc_getchildren_rusage(process: process_t,
                                   children_rusage: *mut rusage_t) -> kern_return_t;
}

//---------------------------------------------------------------------------//
// Safe wrappers                                                             //
//---------------------------------------------------------------------------//

/// (pid, ppid, huérfano) del proceso.
pub fn proc_pids(process: process_t) -> Result<(pid_t, pid_t, bool), kern_return_t> {
    let (mut pid, mut ppid, mut orphaned) = (0, 0, 0);
    let err = unsafe { proc_getpids(process, &mut pid, &mut ppid, &mut orphaned) };
    if err == 0 { Ok((pid, ppid, orphaned != 0)) } else { Err(err) }
}
