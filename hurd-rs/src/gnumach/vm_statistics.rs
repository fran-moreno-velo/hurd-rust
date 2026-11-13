//===========================================================================//
// crate::gnumach::vm_statistics                                             //
//---------------------------------------------------------------------------//
// From gnumach                                                              //
// include/mach/vm_statistics.h                                              //
//===========================================================================//

use crate::gnumach::vm_types::integer_t;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct vm_statistics_data_t {
    pub pagesize: integer_t,         // page size in bytes
    pub free_count: integer_t,       // # of pages free
    pub active_count: integer_t,     // # of pages active
    pub inactive_count: integer_t,   // # of pages inactive
    pub wire_count: integer_t,       // # of pages wired down
    pub zero_fill_count: integer_t,  // # of zero fill pages
    pub reactivations: integer_t,    // # of pages reactivated
    pub pageins: integer_t,          // # of pageins
    pub pageouts: integer_t,         // # of pageouts
    pub faults: integer_t,           // # of faults
    pub cow_faults: integer_t,       // # of copy-on-writes
    pub lookups: integer_t,          // object cache lookups
    pub hits: integer_t,             // object cache hits
}
pub type vm_statistics_t = *mut vm_statistics_data_t;
const _: () = assert!(size_of::<vm_statistics_data_t>() == 13 * 4);

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct pmap_statistics {
    pub resident_count: integer_t,   // # of pages mapped (total)
    pub wired_count: integer_t,      // # of pages wired
}
pub type pmap_statistics_t = *mut pmap_statistics;
