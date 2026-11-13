/* Dynamically allocated port classes/buckets recognized by trivfs.

   Rust port of `trivfs/dynamic-classes.c` from GNU Mach/Hurd.

   This module exports three sets of C‑visible global arrays that
   libtrivfs (C) reads directly:

     trivfs_dynamic_control_port_classes
     trivfs_dynamic_protid_port_classes
     trivfs_dynamic_port_buckets

   Each array is backed by a Rust Vec<*mut T> inside a Mutex for safe
   concurrent mutation.  After every add/remove the C pointer is
   re‑synced to the Vec’s internal buffer (which stays stable until the
   next mutation).  */

use std::sync::Mutex;
use std::ptr::null_mut;
use std::ffi::c_void;
use libc::size_t;

use crate::debug;
use crate::gnuhurd::ports::ports_create_bucket;
use crate::gnuhurd::ports::ports_create_class;
use crate::gnuhurd::ports::port_bucket_t;
use crate::gnuhurd::ports::port_class_t;
use crate::gnuhurd::trivfs::control::trivfs_clean_cntl;
use crate::gnuhurd::trivfs::protid::trivfs_clean_protid;
use crate::gnumach::error::mach_error_t;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::{AtomicPtr, AtomicUsize, Ordering};

pub static DEBUG_ENABLED: AtomicBool = AtomicBool::new(false);

/* No‑op dropweak callback – port classes that do not need weak‑reference
   cleanup pass this as the second argument to ports_create_class.  */
extern "C" fn trivfs_noop_dropweak(_protid: *mut c_void) {}

/* Safe wrappers around the C cleanup functions.

   ports_create_class expects safe `extern "C" fn` pointers, but
   trivfs_clean_cntl / trivfs_clean_protid are declared `unsafe`.
   These wrappers re‑wrap the call so no transmute is required.  */
extern "C" fn trivfs_clean_cntl_wrapper(protid: *mut c_void) {
    trivfs_clean_cntl(protid);
}

extern "C" fn trivfs_clean_protid_wrapper(protid: *mut c_void) {
    unsafe { trivfs_clean_protid(protid) }
}

/* Auxiliary info for each slot in the vector.
   Mirrors `struct aux` from the C source.  */
#[repr(C)]
struct Aux {
    free_el: Option<unsafe extern "C" fn(*mut c_void)>,
    refs: size_t,
}

/* Internal state of a dynamic set.

   `items` stores raw pointers; a null entry (std::ptr::null_mut())
   represents an empty / reusable slot (a "hole").

   `aux` holds one Option<Aux> per slot.  `None` means the slot is
   empty; `Some(Aux{..})` describes the occupant.

   `num` is the count of live (non‑null) elements.  */
struct DynSet<T> {
    items: Vec<*mut T>,
    aux: Vec<Option<Aux>>,
    num: usize,
}

impl<T> DynSet<T> {
    /* Add EL to the set, optionally associating a destructor FREE_EL.

       If EL is already present its reference count is bumped (matching
       the C behaviour of `add_el`).  If a null slot exists (a "hole"
       left by a previous `drop_el`) it is reused.  Otherwise the Vec
       grows automatically – no manual realloc needed.

       Returns Ok(()) on success, Err(ENOMEM) on allocation
       failure (el is null or Vec::try_reserve fails).  */
    fn add(&mut self, el: *mut T, free_el: Option<unsafe extern "C" fn(*mut c_void)>) -> Result<(), i32> {
        // Reject null pointers immediately – matches C's behaviour.
        if el.is_null() {
            debug!("[DEBUG] DynSet::add: el is null, returning ENOMEM");
            return Err(crate::gnumach::error::ENOMEM);
        }

        // Linear scan: look for a matching element or a hole.
        // This mirrors the `for` loop in the C `add_el`.
        for i in 0..self.items.len() {
            if self.items[i].is_null() {
                // Slot is empty (a hole): reuse it.
                // Equivalent to the C branch "if (! (*vec)[i])".
                debug!("[DEBUG] DynSet::add: reusing hole at slot {}", i);
                self.items[i] = el;
                self.aux[i] = Some(Aux { free_el, refs: 1 });
                self.num += 1;
                return Ok(());
            } else if self.items[i] == el {
                // Same pointer already registered – bump refcount.
                // Equivalent to the C branch "(*aux_vec)[i].refs++".
                debug!("[DEBUG] DynSet::add: incrementing refcount for el {:p}", el);
                if let Some(ref mut a) = self.aux[i] {
                    a.refs += 1;
                }
                return Ok(());
            }
        }

        // No hole found and element not yet present: append.
        // Rust's Vec handles growth automatically.
        debug!("[DEBUG] DynSet::add: appending new element {:p}", el);
        if self.items.try_reserve(1).is_err() || self.aux.try_reserve(1).is_err() {
            return Err(crate::gnumach::error::ENOMEM);
        }
        self.items.push(el);
        self.aux.push(Some(Aux { free_el, refs: 1 }));
        self.num += 1;
        Ok(())
    }

    /* Remove (or release) one reference to EL.

       When the reference count reaches zero:
         - the optional destructor FREE_EL is called
         - the slot is set to null (becomes a hole for future reuse)
         - NUM is decremented

       If EL is not found the function silently returns – this matches
       the C drop_el which does the same.  */
    fn drop_el(&mut self, el: *mut T) {
        if el.is_null() {
            return;
        }

        // Linear scan matching the C drop_el loop.
        for i in 0..self.items.len() {
            if self.items[i] == el {
                debug!("[DEBUG] DynSet::drop_el: found el {:p} at slot {}", el, i);
                if let Some(ref mut a) = self.aux[i] {
                    a.refs -= 1;
                    if a.refs == 0 {
                        // Last reference gone: call destructor if any, then
                        // clear the slot (making it a hole).
                        debug!("[DEBUG] DynSet::drop_el: refcount reached zero, freeing slot {}", i);
                        if let Some(f) = a.free_el {
                            unsafe { f(el as *mut c_void) };
                        }
                        self.items[i] = null_mut();
                        self.aux[i] = None;
                        self.num -= 1;
                    } else {
                        debug!("[DEBUG] DynSet::drop_el: refcount now {}", a.refs);
                    }
                }
                return;
            }
        }
        // Element not in set – C code also silently ignores this case.
        debug!("[DEBUG] DynSet::drop_el: el {:p} not found, ignoring", el);
    }
}

// SAFETY: All access to DynSet's internal data is serialised by the
// enclosing Mutex.  Raw pointers in `items` are only dereferenced
// while the lock is held, making it safe to send DynSet across threads.
unsafe impl<T> Send for DynSet<T> {}

/* ===== C‑visible globals =====

   These symbols are accessed directly by libtrivfs (C).  They MUST be
   marked #[unsafe(no_mangle)] and pub static mut so the linker finds
   them when trivfs_io_server / trivfs_fs_server / trivfs_fsys_server
   are called from the demuxer.  */

// --- Control port classes ---

#[unsafe(no_mangle)]
pub static mut trivfs_dynamic_control_port_classes: *mut *mut port_class_t = null_mut();
#[unsafe(no_mangle)]
pub static mut trivfs_num_dynamic_control_port_classes: size_t = 0;

static CONTROL_CLASSES: Mutex<DynSet<port_class_t>> = Mutex::new(DynSet {
    items: Vec::new(),
    aux: Vec::new(),
    num: 0,
});

// --- Protid port classes ---

#[unsafe(no_mangle)]
pub static mut trivfs_dynamic_protid_port_classes: *mut *mut port_class_t = null_mut();
#[unsafe(no_mangle)]
pub static mut trivfs_num_dynamic_protid_port_classes: size_t = 0;

static PROTID_CLASSES: Mutex<DynSet<port_class_t>> = Mutex::new(DynSet {
    items: Vec::new(),
    aux: Vec::new(),
    num: 0,
});

// --- Port buckets ---

#[unsafe(no_mangle)]
pub static mut trivfs_dynamic_port_buckets: *mut *mut port_bucket_t = null_mut();
#[unsafe(no_mangle)]
pub static mut trivfs_num_dynamic_port_buckets: size_t = 0;

static BUCKETS: Mutex<DynSet<port_bucket_t>> = Mutex::new(DynSet {
    items: Vec::new(),
    aux: Vec::new(),
    num: 0,
});

/* Dummy destructor used when no cleanup is needed.
   Mirrors the C pattern of passing `(void(*)(void*))0` to add_el.
   Here we use a real (but empty) function because our Aux stores
   Option<fn>, and the wrapper layer below always passes Some.  */
unsafe extern "C" fn dummy_free(_x: *mut c_void) {}

/* Sync the C‑visible global array pointer to the Vec’s backing store.

   After every mutation of a DynSet the corresponding C globals must be
   updated.  This function writes:

     *c_arr = items.as_ptr()   (or null if empty)
     *c_num = num

   The Vec’s internal buffer is stable until the next mutation (which
   is serialised by the same Mutex), so C can safely iterate `*c_arr`
   for `*c_num` elements between mutations.

   ITEMS – slice of the DynSet's item vector (obtained while holding
           the lock).
   NUM   – live-element count from the DynSet.
   C_ARR – &mut of the C‑visible `*mut *mut T` global.
   C_NUM – &mut of the C‑visible `size_t` global.  */
fn sync_array<T>(items: &[*mut T], num: usize, c_arr: *mut *mut *mut T, c_num: *mut size_t) {
    unsafe {
        let p = if items.is_empty() { null_mut() } else { items.as_ptr() as *mut *mut T };
        AtomicPtr::from_ptr(c_arr).store(p, Ordering::Release);
        AtomicUsize::from_ptr(c_num as *mut usize).store(num as usize, Ordering::Release);
    }
}

/* ===== Public API =====

   These functions are called from control.rs and startup.rs during
   translator initialisation.  They mirror the C interface.  */

/* Add the port class *CLASS to the list of control port classes.
   If *CLASS is null, allocate a new port class and store it.  */
pub fn trivfs_add_control_port_class(class: &mut *mut port_class_t) -> mach_error_t {
    debug!("[DEBUG] trivfs_add_control_port_class: enter, *class={:p}", *class);
    unsafe {
        if (*class).is_null() {
            // Allocate a new control class via ports_create_class.
            // The first argument is the cleanup callback; the second
            // is the dropweak callback (null = no-op).
            *class = ports_create_class(trivfs_clean_cntl_wrapper, trivfs_noop_dropweak);
            debug!("[DEBUG] trivfs_add_control_port_class: allocated new class={:p}", *class);
            if (*class).is_null() {
                debug!("[DEBUG] trivfs_add_control_port_class: allocation failed");
                return crate::gnumach::error::ENOMEM;
            }
        }
        // Lock the DynSet and add the element.
        let mut inner = CONTROL_CLASSES.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        debug!("[DEBUG] trivfs_add_control_port_class: adding to DynSet");
        let r = inner.add(*class, Some(dummy_free as unsafe extern "C" fn(*mut c_void)));
        // Sync C globals while still holding the lock.
        sync_array(&inner.items, inner.num,
                   &raw mut trivfs_dynamic_control_port_classes,
                   &raw mut trivfs_num_dynamic_control_port_classes);
        // Lock released when inner is dropped.
        debug!("[DEBUG] trivfs_add_control_port_class: done, result={:?}", r);
        match r {
            Ok(()) => 0,
            Err(e) => e,
        }
    }
}

/* Remove (dereference) the previously added control port class.  */
pub fn trivfs_remove_control_port_class(class: *mut port_class_t) {
    debug!("[DEBUG] trivfs_remove_control_port_class: enter, class={:p}", class);
    let mut inner = CONTROL_CLASSES.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    inner.drop_el(class);
    sync_array(&inner.items, inner.num,
               &raw mut trivfs_dynamic_control_port_classes,
               &raw mut trivfs_num_dynamic_control_port_classes);
    debug!("[DEBUG] trivfs_remove_control_port_class: done");
}

/* Add the port class *CLASS to the list of protid port classes.
   If *CLASS is null, allocate a new port class and store it.  */
pub fn trivfs_add_protid_port_class(class: &mut *mut port_class_t) -> mach_error_t {
    debug!("[DEBUG] trivfs_add_protid_port_class: enter, *class={:p}", *class);
    unsafe {
        if (*class).is_null() {
            *class = ports_create_class(trivfs_clean_protid_wrapper, trivfs_noop_dropweak);
            debug!("[DEBUG] trivfs_add_protid_port_class: allocated new class={:p}", *class);
            if (*class).is_null() {
                debug!("[DEBUG] trivfs_add_protid_port_class: allocation failed");
                return crate::gnumach::error::ENOMEM;
            }
        }
        let mut inner = PROTID_CLASSES.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        debug!("[DEBUG] trivfs_add_protid_port_class: adding to DynSet");
        let r = inner.add(*class, Some(dummy_free as unsafe extern "C" fn(*mut c_void)));
        sync_array(&inner.items, inner.num,
                   &raw mut trivfs_dynamic_protid_port_classes,
                   &raw mut trivfs_num_dynamic_protid_port_classes);
        debug!("[DEBUG] trivfs_add_protid_port_class: done, result={:?}", r);
        match r {
            Ok(()) => 0,
            Err(e) => e,
        }
    }
}

/* Remove (dereference) the previously added protid port class.  */
pub fn trivfs_remove_protid_port_class(class: *mut port_class_t) {
    debug!("[DEBUG] trivfs_remove_protid_port_class: enter, class={:p}", class);
    let mut inner = PROTID_CLASSES.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    inner.drop_el(class);
    sync_array(&inner.items, inner.num,
               &raw mut trivfs_dynamic_protid_port_classes,
               &raw mut trivfs_num_dynamic_protid_port_classes);
    debug!("[DEBUG] trivfs_remove_protid_port_class: done");
}

/* Add the port bucket *BUCKET to the list of dynamic port buckets.
   If *BUCKET is null, allocate a new bucket and store it.  */
pub fn trivfs_add_port_bucket(bucket: &mut *mut port_bucket_t) -> mach_error_t {
    debug!("[DEBUG] trivfs_add_port_bucket: enter, *bucket={:p}", *bucket);
    unsafe {
        if (*bucket).is_null() {
            *bucket = ports_create_bucket();
            debug!("[DEBUG] trivfs_add_port_bucket: allocated new bucket={:p}", *bucket);
            if (*bucket).is_null() {
                debug!("[DEBUG] trivfs_add_port_bucket: allocation failed");
                return crate::gnumach::error::ENOMEM;
            }
        }
        let mut inner = BUCKETS.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        debug!("[DEBUG] trivfs_add_port_bucket: adding to DynSet");
        let r = inner.add(*bucket, Some(dummy_free as unsafe extern "C" fn(*mut c_void)));
        sync_array(&inner.items, inner.num,
                   &raw mut trivfs_dynamic_port_buckets,
                   &raw mut trivfs_num_dynamic_port_buckets);
        debug!("[DEBUG] trivfs_add_port_bucket: done, result={:?}", r);
        match r {
            Ok(()) => 0,
            Err(e) => e,
        }
    }
}

/* Remove (dereference) the previously added port bucket.  */
pub fn trivfs_remove_port_bucket(bucket: *mut port_bucket_t) {
    debug!("[DEBUG] trivfs_remove_port_bucket: enter, bucket={:p}", bucket);
    let mut inner = BUCKETS.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    inner.drop_el(bucket);
    sync_array(&inner.items, inner.num,
                &raw mut trivfs_dynamic_port_buckets,
                &raw mut trivfs_num_dynamic_port_buckets);
    debug!("[DEBUG] trivfs_remove_port_bucket: done");
}

/* Membership predicates under the same Mutex as the writers: the iterator
   sees a consistent snapshot and the buffer cannot be reallocated in the
   middle of the iteration (the atomic getters below read pointer and
   length separately, a tearable pair). Used by mig_helpers.rs on the hot
   path of every RPC. */
pub fn is_protid_dynamic_class(class: *mut port_class_t) -> bool {
    let inner = PROTID_CLASSES.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    for i in 0..inner.num.min(inner.items.len()) {
        if inner.items[i] == class { return true; }
    }
    false
}

pub fn is_control_dynamic_class(class: *mut port_class_t) -> bool {
    let inner = CONTROL_CLASSES.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    for i in 0..inner.num.min(inner.items.len()) {
        if inner.items[i] == class { return true; }
    }
    false
}

pub fn control_classes() -> (*mut *mut port_class_t, usize) {    unsafe {
        let p = AtomicPtr::from_ptr(
            &raw mut trivfs_dynamic_control_port_classes,
        ).load(Ordering::Acquire);
        let n = AtomicUsize::from_ptr(
            &raw mut trivfs_num_dynamic_control_port_classes,
        ).load(Ordering::Acquire);
        (p, n)
    }
}

pub fn protid_classes() -> (*mut *mut port_class_t, usize) {
    unsafe {
        let p = AtomicPtr::from_ptr(
            &raw mut trivfs_dynamic_protid_port_classes,
        ).load(Ordering::Acquire);
        let n = AtomicUsize::from_ptr(
            &raw mut trivfs_num_dynamic_protid_port_classes,
        ).load(Ordering::Acquire);
        (p, n)
    }
}

pub fn port_buckets() -> (*mut *mut port_bucket_t, usize) {
    unsafe {
        let p = AtomicPtr::from_ptr(
            &raw mut trivfs_dynamic_port_buckets,
        ).load(Ordering::Acquire);
        let n = AtomicUsize::from_ptr(
            &raw mut trivfs_num_dynamic_port_buckets,
        ).load(Ordering::Acquire);
        (p, n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gnuhurd::ports::ports_create_class;

    // #4: the membership predicates (under the Mutex, consistent snapshot)
    // recognize the added dynamic classes and reject the ones that are not.
    // Requires libports (ports_create_class) → runs on the VM.
    #[test]
    fn dynamic_class_membership() {
        let cls = unsafe { ports_create_class(trivfs_clean_protid_wrapper, trivfs_noop_dropweak) };
        assert!(!cls.is_null(), "ports_create_class failed");
        assert!(!is_protid_dynamic_class(cls), "must not be there before adding it");
        let mut c = cls;
        let r = trivfs_add_protid_port_class(&mut c);
        assert_eq!(r, 0, "trivfs_add_protid_port_class failed");
        assert!(is_protid_dynamic_class(cls), "must be there after adding it");
        assert!(!is_protid_dynamic_class(std::ptr::null_mut()), "null is not a dynamic class");
        trivfs_remove_protid_port_class(cls);
        assert!(!is_protid_dynamic_class(cls), "must not be there after removing it");
    }
}