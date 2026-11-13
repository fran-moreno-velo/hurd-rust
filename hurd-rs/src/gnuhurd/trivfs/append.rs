use std::ffi::c_char;
use crate::gnuhurd::trivfs::types::trivfs_control_t;
use crate::gnumach::error::mach_error_t;
use crate::gnumach::error::{EOPNOTSUPP, ENOMEM, ENULLPTR, EINVAL};
use crate::gnuhurd::trivfs::set_options::runtime_argp;
use crate::gnuhurd::trivfs::hooks::Hook;

pub unsafe fn vec_to_argz(
    argz: *mut *mut c_char,
    argz_len: *mut usize,
    s: &str,
) -> mach_error_t {
    let need = s.len() + 1;                       // bytes + NUL
    let newp = libc::realloc(*argz as *mut _, *argz_len + need) as *mut c_char;
    if newp.is_null() { return ENOMEM; }
    let dst = newp.add(*argz_len);
    std::ptr::copy_nonoverlapping(s.as_ptr() as *const c_char, dst, s.len());
    *dst.add(s.len()) = 0;
    *argz = newp;
    *argz_len += need;
    0
}

pub type AppendArgsFn = unsafe extern "C-unwind" fn(
    fsys: *mut trivfs_control_t,
    argz: *mut *mut c_char,
    argz_len: *mut usize,
) -> mach_error_t;

static APPEND_ARGS_HOOK: Hook<AppendArgsFn> = Hook::new();

pub fn register_append_args(f: AppendArgsFn) {
    let _ = APPEND_ARGS_HOOK.set(f);
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn trivfs_append_args(
    fsys: *mut trivfs_control_t,
    argz: *mut *mut c_char,
    argz_len: *mut usize,
) -> mach_error_t {
    match APPEND_ARGS_HOOK.get() {
        Some(f) => f(fsys, argz, argz_len),
        None => {
            let Some(ap) = runtime_argp() else { return EOPNOTSUPP; };
            if ap.options.is_null() { return ENULLPTR; }
            let mut oi = 0usize;
            loop {
                // Defensive bound: a table without a sentinel (name == NULL)
                // must not produce an infinite OOB iteration.
                if oi > 1024 { return EINVAL; }
                let opt = unsafe { &*ap.options.add(oi) };
                if opt.name.is_null() { break; }
                let name = unsafe { std::ffi::CStr::from_ptr(opt.name) }.to_str().unwrap_or("");
                // Solo opciones reales: omitir alias/hidden/doc.
                let real = (opt.flags & (crate::gnuhurd::trivfs::set_options::OPTION_ALIAS
                    | crate::gnuhurd::trivfs::set_options::OPTION_HIDDEN
                    | crate::gnuhurd::trivfs::set_options::OPTION_DOC)) == 0;
                if real {
                    let entry = if !opt.arg.is_null() {
                        let arg = unsafe { std::ffi::CStr::from_ptr(opt.arg) }.to_str().unwrap_or("");
                        format!("{name}={arg}")
                    } else {
                        name.to_string()
                    };
                    let e = unsafe { vec_to_argz(argz, argz_len, &entry) };
                    if e != 0 { return e; }
                }
                oi += 1;
            }
            0
        }
    }
}