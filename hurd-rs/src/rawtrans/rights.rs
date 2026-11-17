//===================================================================================//
// rawtrans::rights: derechos de puerto de los objetos del servidor                  //
//===================================================================================//
// Antes era el submódulo sys::ports.  Se llama "rights" para no confundirlo con
// gnuhurd::ports (libports).

use crate::gnumach::kern_return::{kern_return_t, KERN_SUCCESS};
use crate::gnumach::message::MACH_MSG_TYPE_MAKE_SEND_ONCE;
use crate::gnumach::notify::MACH_NOTIFY_NO_SENDERS;
use crate::gnumach::port::{mach_port_allocate, mach_port_deallocate, mach_port_mod_refs,
                           mach_port_move_member, mach_port_request_notification,
                           mach_port_t, MACH_PORT_NULL, MACH_PORT_RIGHT_RECEIVE};
use crate::gnumach::task::mach_task_self;

/// Libera un derecho de envío que el receptor ya no necesita.
pub fn port_deallocate(name: mach_port_t) {
    if name == MACH_PORT_NULL {
        return;
    }
    unsafe {
        mach_port_deallocate(mach_task_self(), name);
    }
}


/// Crea un receive right nuevo.
pub fn allocate_receive() -> Result<mach_port_t, kern_return_t> {
    {
        let mut name = MACH_PORT_NULL;
        // SAFETY: puntero válido.
        match unsafe { mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &mut name) } {
            KERN_SUCCESS => Ok(name),
            kr => Err(kr),
        }
    }
}

/// Mete `port` en el port set `set` (donde escucha el bucle de servicio).
pub fn move_member(port: mach_port_t, set: mach_port_t) -> Result<(), kern_return_t> {
    match unsafe { mach_port_move_member(mach_task_self(), port, set) } {
        KERN_SUCCESS => Ok(()),
        kr => Err(kr),
    }
}

/// Pide al kernel una notificación no-senders, entregada en el propio `port`,
/// cuando desaparezca el último send right creado con MAKE_SEND (sync = 1: el
/// primer MAKE_SEND es el de la respuesta a fsys_getroot).
pub fn request_no_senders(port: mach_port_t) -> Result<(), kern_return_t> {
    {
        let mut previous = MACH_PORT_NULL;
        // SAFETY: puntero válido; `port` es un receive right nuestro.
        let kr = unsafe {
            mach_port_request_notification(
                mach_task_self(), port, MACH_NOTIFY_NO_SENDERS, 1, port,
                MACH_MSG_TYPE_MAKE_SEND_ONCE, &mut previous,
            )
        };
        if kr != KERN_SUCCESS {
            return Err(kr);
        }
        port_deallocate(previous);
        Ok(())
    }
}

/// Destruye el receive right (y con él los send rights que tengan los clientes).
pub fn destroy_receive(port: mach_port_t) {
    unsafe {
        mach_port_mod_refs(mach_task_self(), port, MACH_PORT_RIGHT_RECEIVE, -1);
    }
}
