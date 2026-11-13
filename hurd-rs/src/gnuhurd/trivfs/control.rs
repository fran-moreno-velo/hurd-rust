//===========================================================================//
// crate::hurd::trivfs                                                       //
//---------------------------------------------------------------------------//
// From github - gnuhurd                                                     //
// /hurd/libtrivfs/trivfs.h                                                  //
//===========================================================================//

// Import types

use crate::gnuhurd::ports::port_bucket_t;
use crate::gnuhurd::ports::port_class_t;
use crate::gnuhurd::trivfs::dynamic::trivfs_add_control_port_class;
use crate::gnuhurd::trivfs::dynamic::trivfs_add_port_bucket;
use crate::gnuhurd::trivfs::dynamic::trivfs_add_protid_port_class;
use crate::gnuhurd::trivfs::dynamic::trivfs_remove_control_port_class;
use crate::gnuhurd::trivfs::dynamic::trivfs_remove_port_bucket;
use crate::gnuhurd::trivfs::dynamic::trivfs_remove_protid_port_class;
use crate::gnuhurd::trivfs::types::trivfs_control_t;
use crate::gnumach::error::mach_error_t;
use crate::gnumach::port::mach_port_deallocate;
use crate::gnumach::port::mach_port_t;

use std::ffi::c_void;

// Import constants

use crate::gnumach::error::ERR_NONE;
use crate::gnumach::port::MACH_PORT_NULL;
use crate::gnumach::port::MACH_PORT_RIGHT_RECEIVE;

// Import functions

use crate::gnumach::port::mach_port_allocate;
use crate::gnumach::port::mach_port_destroy;
use crate::gnumach::task::mach_task_self;

use crate::gnuhurd::ports::ports_create_port;
use crate::gnuhurd::ports::ports_port_deref;

use crate::debug;


//---------------------------------------------------------------------------//
// Translated functions                                                      //
//---------------------------------------------------------------------------//

/* Create a new trivfs control port, with underlying node UNDERLYING, and
return it in CONTROL.  CONTROL_CLASS & CONTROL_BUCKET are passed to
the ports library to create the control port, and PROTID_CLASS &
PROTID_BUCKET are used when creating ports representing opens of this
node.  */
pub fn trivfs_create_control(
    underlying: mach_port_t,
    mut control_class: *mut port_class_t,
    mut control_bucket: *mut port_bucket_t,
    mut protid_class: *mut port_class_t,
    mut protid_bucket: *mut port_bucket_t,
    control: *mut *mut trivfs_control_t,
) -> mach_error_t {
    debug!("[DEBUG] trivfs_create_control enter");

    let mut err: mach_error_t;
    err = trivfs_add_control_port_class(&mut control_class);

    debug!("[DEBUG] add_control_port_class: {}", err);

    if err == ERR_NONE {
        err = trivfs_add_protid_port_class(&mut protid_class)
    } else {
        protid_class = std::ptr::null_mut()
    };

    if err == ERR_NONE {
        err = trivfs_add_port_bucket(&mut control_bucket)
    } else {
        control_bucket = std::ptr::null_mut()
    };

    if err == ERR_NONE {
        if protid_bucket.is_null() {
            protid_bucket = control_bucket
        };
        err = trivfs_add_port_bucket(&mut protid_bucket)
    } else {
        protid_bucket = std::ptr::null_mut()
    };

    if err == ERR_NONE {
        err = unsafe {
            ports_create_port(
                control_class,
                control_bucket,
                std::mem::size_of::<trivfs_control_t>(),
                control as *mut c_void,
            )
        };

        debug!("[DEBUG] ports_create_port: {}", err);
    };

    unsafe{
        if err == ERR_NONE {
            let cntl = &mut **control;
            cntl.underlying = underlying;
            cntl.protid_class = protid_class;
            cntl.protid_bucket = protid_bucket;
            // Init to MACH_PORT_NULL: if mach_port_allocate fails,
            // trivfs_clean_cntl (via ports_port_deref) must not destroy a
            // garbage port name.
            cntl.filesys_id = MACH_PORT_NULL;
            cntl.file_id = MACH_PORT_NULL;
            err = mach_port_allocate(
                mach_task_self(),
                MACH_PORT_RIGHT_RECEIVE,
                &mut cntl.filesys_id,
            );
            if err != ERR_NONE {
                ports_port_deref((*control) as *mut c_void)
            } else {
                err = mach_port_allocate(
                    mach_task_self(),
                    MACH_PORT_RIGHT_RECEIVE,
                    &mut cntl.file_id,
                );
                if err != ERR_NONE {
                    mach_port_destroy(mach_task_self(), cntl.filesys_id);
                    ports_port_deref((*control) as *mut c_void)
                } else {
                    cntl.hook = std::ptr::null_mut();
                }
            }
        }
    }

    if err != ERR_NONE {
        trivfs_remove_control_port_class(control_class);
        trivfs_remove_protid_port_class(protid_class);
        trivfs_remove_port_bucket(control_bucket);
        trivfs_remove_port_bucket(protid_bucket);
    }

    err
}

/* Clean pointers in a struct trivfs_control when its last reference
   vanishes before it's freed. */
pub fn trivfs_clean_cntl(arg: *mut c_void)
{
  let cntl: *mut trivfs_control_t = arg as *mut trivfs_control_t;
  
  unsafe{
    let cnt_ref = &*cntl;
    mach_port_destroy (mach_task_self (), cnt_ref.filesys_id);
    mach_port_destroy (mach_task_self (), cnt_ref.file_id);
    mach_port_deallocate (mach_task_self (), cnt_ref.underlying);
    
    // Don't call trivfs_remove_* — C never actually frees them. This can be recovered when all MIG stubs are ported to Rust
    // (dynamic_*_sz stays at 0 → drop_el is a no-op)
    // Would also clear trivfs_dynamic_* which the MIG stubs need
  }
}