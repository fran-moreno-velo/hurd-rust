use std::ffi::c_int;
use std::sync::atomic::{AtomicI32, Ordering};

unsafe extern "C" {
    static mut trivfs_fsid: c_int;
    static mut trivfs_fstype: c_int;
    static mut trivfs_allow_open: c_int;
    static mut trivfs_support_read: c_int;
    static mut trivfs_support_write: c_int;
    static mut trivfs_support_exec: c_int;
}

fn load_i32(sym: *mut c_int) -> c_int {
    unsafe { AtomicI32::from_ptr(sym).load(Ordering::Acquire) }
}

fn store_i32(sym: *mut c_int, v: c_int) {
    unsafe { AtomicI32::from_ptr(sym).store(v, Ordering::Release) };
}

/// Atomic setters (Release): translators should use them instead of writing
/// the `static mut` directly, so the write stays synchronized with the
/// library's `Acquire` reads even if done after the multithreaded demuxer
/// starts. The `#[no_mangle]` symbols are kept (C ABI).
pub fn set_fsid(v: c_int) { store_i32(&raw mut trivfs_fsid, v); }
pub fn set_fstype(v: c_int) { store_i32(&raw mut trivfs_fstype, v); }
pub fn set_allow_open(v: c_int) { store_i32(&raw mut trivfs_allow_open, v); }
pub fn set_support_read(v: c_int) { store_i32(&raw mut trivfs_support_read, v); }
pub fn set_support_write(v: c_int) { store_i32(&raw mut trivfs_support_write, v); }
pub fn set_support_exec(v: c_int) { store_i32(&raw mut trivfs_support_exec, v); }

/// fsid with atomic lazy-init (fetch_update): if a translator did not set it in
/// main, the first statfs/stat initializes it with its pid safely.
pub fn fsid() -> c_int {
    let v = load_i32(&raw mut trivfs_fsid);
    if v != 0 { return v; }
    let a = unsafe { AtomicI32::from_ptr(&raw mut trivfs_fsid) };
    let pid = std::process::id() as c_int;
    a.fetch_update(Ordering::AcqRel, Ordering::Acquire,
        |cur| if cur == 0 { Some(pid) } else { None }).unwrap_or(pid)
}

pub fn fstype() -> c_int { load_i32(&raw mut trivfs_fstype) }
pub fn allow_open() -> c_int { load_i32(&raw mut trivfs_allow_open) }
pub fn support_read() -> c_int { load_i32(&raw mut trivfs_support_read) }
pub fn support_write() -> c_int { load_i32(&raw mut trivfs_support_write) }
pub fn support_exec() -> c_int { load_i32(&raw mut trivfs_support_exec) }

#[cfg(test)]
mod tests {
    use super::*;

    // #3: the atomic setters (Release) are read by the getters (Acquire).
    // In the test build the symbols come from the `test_abi_syms` shim
    // (trivfs.rs), not from a real translator.
    #[test]
    fn setters_roundtrip() {
        set_fstype(0x1234);
        assert_eq!(fstype(), 0x1234);
        set_allow_open(3);
        assert_eq!(allow_open(), 3);
        set_support_read(0);
        assert_eq!(support_read(), 0);
        set_support_write(0);
        assert_eq!(support_write(), 0);
        set_support_exec(1);
        assert_eq!(support_exec(), 1);
    }

    // #3: the fsid lazy-init (fetch_update) is safe with N threads: all of
    // them get the same non-zero value, with no tearing or races.
    #[test]
    fn fsid_lazy_init_concurrent() {
        set_fsid(0);
        let handles: Vec<_> = (0..8)
            .map(|_| std::thread::spawn(|| fsid()))
            .collect();
        let vals: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        for v in &vals {
            assert_ne!(*v, 0, "fsid() must not return 0 after the lazy-init");
            assert_eq!(*v, vals[0], "all threads must see the same fsid");
        }
    }
}