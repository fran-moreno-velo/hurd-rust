use std::ffi::c_int;
use crate::gnuhurd::io::idvec;
use libc::uid_t;

pub(crate) fn idvec_contains(v: &idvec, id: uid_t) -> bool {
    if v.ids.is_null() || v.num == 0 { return false; }
    let s = unsafe { std::slice::from_raw_parts(v.ids, v.num as usize) };
    s.contains(&id)
}

// clone priv.h:29-32 → is_privileged
#[unsafe(no_mangle)]
pub unsafe extern "C" fn _is_privileged(uids: *mut idvec) -> c_int {
    if uids.is_null() { return 0; }
    let u = unsafe { &*uids };
    (idvec_contains(u, 0) || idvec_contains(u, libc::getuid())) as c_int
}