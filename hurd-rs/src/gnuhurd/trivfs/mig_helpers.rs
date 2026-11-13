use core::ptr;
use std::ffi::c_void;
use crate::gnumach::port::mach_port_t;
use crate::gnuhurd::ports::{
    ports_lookup_port, ports_lookup_payload, ports_port_deref, port_info_t,
};
use crate::gnuhurd::trivfs::types::{trivfs_protid_t, trivfs_control_t};
use crate::gnuhurd::trivfs::dynamic::{is_protid_dynamic_class, is_control_dynamic_class};

pub fn trivfs_begin_using_protid(port: mach_port_t) -> *mut trivfs_protid_t {
    unsafe {
        let pi = ports_lookup_port(ptr::null_mut(), port, ptr::null_mut()) as *mut port_info_t;
        if !pi.is_null() {
            if is_protid_dynamic_class((*pi).class) {
                return pi as *mut trivfs_protid_t;
            }
            ports_port_deref(pi as *mut c_void);
        }
    }
    ptr::null_mut()
}

pub fn trivfs_begin_using_protid_payload(payload: usize) -> *mut trivfs_protid_t {
    unsafe {
        let pi = ports_lookup_payload(ptr::null_mut(), payload, ptr::null_mut()) as *mut port_info_t;
        if !pi.is_null() {
            if is_protid_dynamic_class((*pi).class) {
                return pi as *mut trivfs_protid_t;
            }
            ports_port_deref(pi as *mut c_void);
        }
    }
    ptr::null_mut()
}

pub fn trivfs_end_using_protid(protid: *mut trivfs_protid_t) {
    unsafe { if !protid.is_null() { ports_port_deref(protid as *mut c_void); } }
}

pub fn trivfs_convert_to_port(protid: *mut trivfs_protid_t) -> mach_port_t {
    unsafe { (*protid).pi.port_right }
}

pub fn trivfs_begin_using_control(port: mach_port_t) -> *mut trivfs_control_t {
    unsafe {
        let pi = ports_lookup_port(ptr::null_mut(), port, ptr::null_mut()) as *mut port_info_t;
        if !pi.is_null() {
            if is_control_dynamic_class((*pi).class) {
                return pi as *mut trivfs_control_t;
            }
            ports_port_deref(pi as *mut c_void);
        }
    }
    ptr::null_mut()
}

pub fn trivfs_begin_using_control_payload(payload: usize) -> *mut trivfs_control_t {
    unsafe {
        let pi = ports_lookup_payload(ptr::null_mut(), payload, ptr::null_mut()) as *mut port_info_t;
        if !pi.is_null() {
            if is_control_dynamic_class((*pi).class) {
                return pi as *mut trivfs_control_t;
            }
            ports_port_deref(pi as *mut c_void);
        }
    }
    ptr::null_mut()
}

pub fn trivfs_end_using_control(control: *mut trivfs_control_t) {
    unsafe { if !control.is_null() { ports_port_deref(control as *mut c_void); } }
}

/// RAII guard: calls `trivfs_end_using_protid` on drop, also when the RPC
/// handler panics (the unwind crosses the server's `catch_unwind` and the
/// `Drop` runs), avoiding a protid refcount leak (§9.1). On the normal path
/// the deref happens at function exit instead of on the explicit
/// `trivfs_end_using_protid(...)` line (now removed).
pub struct ProtidGuard(*mut trivfs_protid_t);
impl ProtidGuard {
    pub fn new(p: *mut trivfs_protid_t) -> Self { Self(p) }
}
impl Drop for ProtidGuard {
    fn drop(&mut self) { trivfs_end_using_protid(self.0); }
}

/// Same for the control (fsys_server).
pub struct ControlGuard(*mut trivfs_control_t);
impl ControlGuard {
    pub fn new(p: *mut trivfs_control_t) -> Self { Self(p) }
}
impl Drop for ControlGuard {
    fn drop(&mut self) { trivfs_end_using_control(self.0); }
}