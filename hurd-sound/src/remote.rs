//===================================================================================//
// remote: clientes en otra tarea (o en otro hilo)                                   //
//===================================================================================//
//
// Lado servidor: RemoteClient implementa engine::Process.  En cada ciclo copia las
// entradas al segmento, despierta al cliente y espera su aviso con un plazo de un
// periodo.  Si el cliente llega tarde, sus salidas cuentan como silencio en ese
// ciclo; tras MAX_LATE ciclos tardíos seguidos se le da por muerto y el motor lo
// quita del grafo (como hace JACK con los clientes que no cumplen el plazo).
//
// Lado cliente: run_client() es el bucle del cliente: espera el despertar, llama
// a RemoteProcess::process con los búferes del segmento y avisa al terminar.

use std::sync::atomic::Ordering;
use std::time::Duration;

use crate::engine::{Ports, Process};
use crate::graph::{Direction, PortId};
use crate::segment::Segment;
use crate::signal::{ClientSignal, ServerSignal};
use crate::{Error, Result};

/// Ciclos tardíos seguidos tras los que se desconecta al cliente.
pub const MAX_LATE: u32 = 8;

pub struct RemoteClient<S: ServerSignal> {
    seg: Segment,
    sig: S,
    /// Id en el grafo del puerto i del segmento.
    ports: Vec<PortId>,
    timeout: Duration,
    late_in_a_row: u32,
    alive: bool,
    /// Último ciclo enviado al cliente (0 = ninguno).
    sent: u64,
}

impl<S: ServerSignal> RemoteClient<S> {
    /// `ports[i]` es el id en el grafo del puerto i del segmento.
    pub fn new(seg: Segment, sig: S, ports: Vec<PortId>) -> Self {
        assert_eq!(ports.len(), seg.nports());
        let timeout = Duration::from_nanos(seg.format().period_ns()).max(Duration::from_millis(1));
        RemoteClient { seg, sig, ports, timeout, late_in_a_row: 0, alive: true, sent: 0 }
    }

    /// Plazo para que el cliente termine un ciclo (por defecto, un periodo).
    pub fn set_timeout(&mut self, t: Duration) { self.timeout = t; }

    /// Ciclos en los que el cliente llegó tarde.
    pub fn late(&self) -> u64 { self.seg.header().late.load(Ordering::Relaxed) }

    fn wait(&mut self, cycle: u64) -> Result<bool> {
        let deadline = std::time::Instant::now() + self.timeout;
        loop {
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            if !self.sig.wait_done(left)? {
                return Ok(false);
            }
            // Un aviso atrasado de un ciclo anterior no cuenta.
            if self.seg.header().done.load(Ordering::Acquire) == cycle {
                return Ok(true);
            }
        }
    }
}

impl<S: ServerSignal> RemoteClient<S> {
    /// Ciclo perdido: salidas en silencio y cuenta para la desconexión.
    fn missed(&mut self, p: &mut Ports<'_>) {
        self.seg.header().late.fetch_add(1, Ordering::Relaxed);
        self.late_in_a_row += 1;
        if self.late_in_a_row >= MAX_LATE {
            self.alive = false;
        }
        for (i, &id) in self.ports.iter().enumerate() {
            if self.seg.port_dir(i) == Direction::Output {
                p.output(id).fill(0.0);
            }
        }
    }
}

impl<S: ServerSignal> Process for RemoteClient<S> {
    fn process(&mut self, p: &mut Ports<'_>) {
        if !self.alive {
            return;
        }
        // Si el cliente aún no ha terminado el ciclo anterior, sigue usando el
        // segmento: no se le toca ni se le despierta; este ciclo es silencio.
        if self.sent != 0 && self.seg.header().done.load(Ordering::Acquire) != self.sent {
            self.missed(p);
            return;
        }
        // Entradas -> segmento.
        for (i, &id) in self.ports.iter().enumerate() {
            if self.seg.port_dir(i) == Direction::Input {
                // SAFETY: el cliente no toca el segmento hasta que lo despertamos.
                unsafe { self.seg.buffer(i) }.copy_from_slice(p.input(id));
            }
        }
        let cycle = p.cycle + 1; // 0 queda para "nunca procesado"
        self.seg.header().cycle.store(cycle, Ordering::Release);
        self.sent = cycle;

        let r = self.sig.wake().and_then(|()| self.wait(cycle));
        match r {
            Ok(true) => {}
            Err(Error::Disconnected) => {
                // El cliente ha muerto: fuera del grafo en este mismo ciclo.
                self.alive = false;
                self.missed(p);
                return;
            }
            Ok(false) | Err(_) => {
                self.missed(p);
                return;
            }
        }
        self.late_in_a_row = 0;

        // Segmento -> salidas.
        for (i, &id) in self.ports.iter().enumerate() {
            if self.seg.port_dir(i) == Direction::Output {
                // SAFETY: el cliente ha avisado de que terminó este ciclo.
                p.output(id).copy_from_slice(unsafe { self.seg.buffer(i) });
            }
        }
    }

    fn alive(&self) -> bool { self.alive }
}

//-----------------------------------------------------------------------------------//
// Lado cliente                                                                      //
//-----------------------------------------------------------------------------------//

/// Código de un cliente remoto.  Se llama una vez por ciclo.
pub trait RemoteProcess {
    fn process(&mut self, ports: &mut ClientPorts<'_>);
}

/// Búferes del cliente durante un ciclo, por índice de puerto en el segmento.
pub struct ClientPorts<'a> {
    seg: &'a Segment,
    pub cycle: u64,
}

impl ClientPorts<'_> {
    pub fn len(&self) -> usize { self.seg.nports() }
    pub fn is_empty(&self) -> bool { self.len() == 0 }
    pub fn name(&self, i: usize) -> &str { self.seg.port_name(i) }

    pub fn input(&self, i: usize) -> &[f32] {
        assert_eq!(self.seg.port_dir(i), Direction::Input, "no es una entrada");
        // SAFETY: estamos entre el despertar y el aviso de fin.
        unsafe { self.seg.buffer(i) }
    }

    pub fn output(&mut self, i: usize) -> &mut [f32] {
        assert_eq!(self.seg.port_dir(i), Direction::Output, "no es una salida");
        // SAFETY: estamos entre el despertar y el aviso de fin.
        unsafe { self.seg.buffer(i) }
    }
}

/// Bucle del cliente.  Vuelve cuando el servidor cierra el segmento o se va.
pub fn run_client<C: ClientSignal>(seg: &Segment, sig: &mut C,
                                   proc_: &mut dyn RemoteProcess) -> Result<()> {
    loop {
        if !sig.wait_wake()? {
            return Ok(());
        }
        let h = seg.header();
        if h.shutdown.load(Ordering::Acquire) != 0 {
            return Ok(());
        }
        let cycle = h.cycle.load(Ordering::Acquire);
        proc_.process(&mut ClientPorts { seg, cycle });
        h.done.store(cycle, Ordering::Release);
        sig.done()?;
    }
}
