use crate::gnuhurd::trivfs::hooks::Hook;
use crate::gnuhurd::trivfs::types::{trivfs_node_t, trivfs_peropen_t, trivfs_protid_t};
use std::ptr::null_mut;

pub type MakePeropenFn = unsafe extern "C-unwind" fn(
    cred: *mut trivfs_protid_t,
) -> *mut trivfs_peropen_t;

pub type MakeNodeFn = unsafe extern "C-unwind" fn(
    po: *mut trivfs_peropen_t,
) -> *mut trivfs_node_t;

static MAKE_PEROPEN_HOOK: Hook<MakePeropenFn> = Hook::new();
static MAKE_NODE_HOOK: Hook<MakeNodeFn> = Hook::new();

pub fn register_make_peropen(f: MakePeropenFn) {
    let _ = MAKE_PEROPEN_HOOK.set(f);
}

pub fn register_make_node(f: MakeNodeFn) {
    let _ = MAKE_NODE_HOOK.set(f);
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn trivfs_make_peropen(
    cred: *mut trivfs_protid_t,
) -> *mut trivfs_peropen_t {
    match MAKE_PEROPEN_HOOK.get() {
        Some(f) => f(cred),
        None => null_mut(),
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn trivfs_make_node(
    po: *mut trivfs_peropen_t,
) -> *mut trivfs_node_t {
    match MAKE_NODE_HOOK.get() {
        Some(f) => f(po),
        None => null_mut(),
    }
}