use std::ffi::{c_char, c_int, c_void};
use std::sync::atomic::{AtomicPtr, Ordering};

use crate::gnuhurd::trivfs::hooks::Hook;
use crate::gnumach::error::mach_error_t;
use crate::gnumach::error::{EINVAL, EOPNOTSUPP, ENULLPTR};
use crate::gnuhurd::trivfs::types::trivfs_control_t;

// OPTION_* flags (glibc argp.h).
pub const OPTION_ARG_OPTIONAL: c_int = 0x1;
pub const OPTION_HIDDEN: c_int = 0x2;
pub const OPTION_ALIAS: c_int = 0x4;
pub const OPTION_DOC: c_int = 0x8;
pub const OPTION_NO_USAGE: c_int = 0x10;

/// struct argp_option (glibc argp.h) — layout C completo.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ArgpOption {
    pub name: *const c_char,   // NULL == end of table
    pub key: c_int,            // > 0 and printable → also a short option
    pub arg: *const c_char,    // argument name (NULL = no argument)
    pub flags: c_int,          // OPTION_*
    pub doc: *const c_char,
    pub group: c_int,
}

/// struct argp (glibc argp.h) — only the fields trivfs uses.
#[repr(C)]
pub struct argp {
    pub options: *const ArgpOption,
    pub parse: Option<unsafe extern "C" fn(
        input: *mut c_void,
        key: c_int,
        arg: *const c_char,
    ) -> mach_error_t>,
}

#[unsafe(no_mangle)]
pub static mut trivfs_runtime_argp: *mut argp = std::ptr::null_mut();

pub fn runtime_argp() -> Option<&'static argp> {
    let p = unsafe { AtomicPtr::from_ptr(&raw mut trivfs_runtime_argp) }.load(Ordering::Acquire);
    unsafe { p.as_ref() }
}
pub fn set_runtime_argp(p: *mut argp) {
    unsafe { AtomicPtr::from_ptr(&raw mut trivfs_runtime_argp) }.store(p, Ordering::Release);
}

pub type SetOptionsFn = unsafe extern "C-unwind" fn(
    fsys: *mut trivfs_control_t,
    argz: *const c_char,
    argz_len: usize,
) -> mach_error_t;

static SET_OPTIONS_HOOK: Hook<SetOptionsFn> = Hook::new();

pub fn register_set_options(f: SetOptionsFn) { let _ = SET_OPTIONS_HOOK.set(f); }

/// Convert an argz (NUL-separated) into a Vec of tokens, like argz_extract.
pub unsafe fn argz_to_vec(argz: *const c_char, argz_len: usize) -> Vec<String> {
    if argz.is_null() { return Vec::new(); }
    let buf = std::slice::from_raw_parts(argz as *const u8, argz_len);
    buf.split(|&b| b == 0)
        .filter(|s| !s.is_empty())
        .map(|s| String::from_utf8_lossy(s).into_owned())
        .collect()
}

/// Is this a short option (key > 0 and printable)?
fn is_short_key(key: c_int) -> bool {
    key > 0 && (32..=126).contains(&key)
}

/// Find the table option whose long name or short key matches `name`. If
/// `allow_abbrev`, accept a unique prefix of a long name.
/// Returns (index in the table, key to use).
fn find_option(
    ap: &argp,
    name: &str,
    is_long: bool,
    allow_abbrev: bool,
) -> Option<usize> {
    // Table count (ends at name == NULL). Defensive bound: a table without a
    // sentinel must not produce an infinite OOB iteration.
    let mut count = 0usize;
    unsafe {
        while count < 1024 && !(*ap.options.add(count)).name.is_null() { count += 1; }
    }
    let opts = unsafe { std::slice::from_raw_parts(ap.options, count) };

    if is_long {
        // Long name exacto.
        for (i, o) in opts.iter().enumerate() {
            if !o.name.is_null() {
                let n = unsafe { std::ffi::CStr::from_ptr(o.name) }.to_bytes();
                if n == name.as_bytes() { return Some(i); }
            }
        }
        // Unique abbreviation (argp getopt: unambiguous prefix).
        if allow_abbrev {
            let mut found: Option<usize> = None;
            let mut ambiguous = false;
            for (i, o) in opts.iter().enumerate() {
                if !o.name.is_null() && (o.flags & OPTION_ALIAS) == 0 {
                    let n = unsafe { std::ffi::CStr::from_ptr(o.name) }.to_bytes();
                    if n.starts_with(name.as_bytes()) {
                        if found.is_some() { ambiguous = true; }
                        found = Some(i);
                    }
                }
            }
            if !ambiguous { return found; }
        }
    } else {
        // Short key.
        let key = name.as_bytes()[0] as c_int;
        for (i, o) in opts.iter().enumerate() {
            if is_short_key(o.key) && o.key == key { return Some(i); }
        }
    }
    None
}

    /// Is the "help" option that ARGP_NO_HELP discards (ignored).
fn is_help(name: &str) -> bool {
    name == "--help" || name == "-h" || name == "help" || name == "h"
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn trivfs_set_options(
    fsys: *mut trivfs_control_t,
    argz: *const c_char,
    argz_len: usize,
) -> mach_error_t {
    if let Some(f) = SET_OPTIONS_HOOK.get() {
        return f(fsys, argz, argz_len);
    }
    let Some(ap) = runtime_argp() else {
        return EOPNOTSUPP;
    };
    if ap.options.is_null() { return ENULLPTR; }

    let tokens = unsafe { argz_to_vec(argz, argz_len) };
    if tokens.is_empty() { return 0; }

    // fsysopts builds the argz with `argv + state->next` (no argv0), so the
    // tokens are only the real options; they are all parsed from 0.
    let mut i = 0;
    while i < tokens.len() {
        let tok = &tokens[i];

        if tok.starts_with("--") {
            // Long option: --name, --name=value, o --name value.
            let body = &tok[2..];
            let (name, inline_val) = match body.split_once('=') {
                Some((n, v)) => (n, Some(v.to_string())),
                None => (body, None),
            };
            if is_help(name) { i += 1; continue; }

            let Some(idx) = find_option(ap, name, true, true) else { return EINVAL; };
            let opt = *unsafe { &*ap.options.add(idx) };
            let key = opt.key;
            let has_arg = !opt.arg.is_null();
            let arg_optional = (opt.flags & OPTION_ARG_OPTIONAL) != 0;

            let mut val: Option<String> = inline_val;
            if val.is_none() && has_arg && !arg_optional {
                // --name value (token siguiente).
                if i + 1 < tokens.len() {
                    i += 1;
                    val = Some(tokens[i].clone());
                } else {
                    return EINVAL; // missing the argument
                }
            }

            if let Some(parse) = ap.parse {
                let carg = val.and_then(|v| std::ffi::CString::new(v).ok());
                let arg_ptr = carg.as_ref().map_or(std::ptr::null(), |s| s.as_ptr());
                let err = unsafe { parse(fsys as *mut c_void, key, arg_ptr) };
                if err != 0 { return err; }
            }
            i += 1;
        } else if tok.starts_with('-') && tok.len() > 1 && !tok.starts_with("--") {
            // Short option: -c, -cvalue, -c value.
            if is_help(&tok[1..2]) { i += 1; continue; }

            let Some(idx) = find_option(ap, &tok[1..2], false, false) else { return EINVAL; };
            let opt = *unsafe { &*ap.options.add(idx) };
            let key = opt.key;
            let has_arg = !opt.arg.is_null();
            let arg_optional = (opt.flags & OPTION_ARG_OPTIONAL) != 0;

            let mut val: Option<String> = None;
            if has_arg && !arg_optional {
                if tok.len() > 2 {
                    // -cvalue
                    val = Some(tok[2..].to_string());
                } else if i + 1 < tokens.len() {
                    // -c value
                    i += 1;
                    val = Some(tokens[i].clone());
                } else {
                    return EINVAL;
                }
            } else if has_arg && arg_optional && tok.len() > 2 {
                val = Some(tok[2..].to_string());
            }

            if let Some(parse) = ap.parse {
                let carg = val.and_then(|v| std::ffi::CString::new(v).ok());
                let arg_ptr = carg.as_ref().map_or(std::ptr::null(), |s| s.as_ptr());
                let err = unsafe { parse(fsys as *mut c_void, key, arg_ptr) };
                if err != 0 { return err; }
            }
            i += 1;
        } else {
            // Not an option: C passes it to ARGP_KEY_ARG (ignored here).
            return EINVAL;
        }
    }
    0
}
