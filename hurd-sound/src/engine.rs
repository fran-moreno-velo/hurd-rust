//===================================================================================//
// engine: ciclo de proceso y mezcla                                                 //
//===================================================================================//
//
// Un ciclo:
//   1. backend.wait()            el dispositivo pide el siguiente periodo
//   2. backend.read()            captura -> puertos system:capture_N
//   3. para cada cliente, en orden topológico:
//        entradas = suma de las salidas conectadas
//        cliente.process()       llena sus salidas
//   4. system:playback_N = suma de las salidas conectadas
//   5. backend.write()
//
// En este paso los clientes son objetos del mismo proceso (trait Process).  En el
// paso 2 el paso 3 despertará a clientes de otras tareas, con los búferes de sus
// puertos en memoria compartida; la interfaz Ports está pensada para no cambiar.

use std::collections::BTreeMap;

use crate::backend::{Backend, Wakeup};
use crate::graph::{ClientId, Direction, Graph, PortId, SYSTEM};
use crate::{Error, Format, Result};

/// Código de un cliente.  Se llama una vez por periodo, en el hilo del servidor:
/// no debe bloquearse ni reservar memoria.
pub trait Process {
    fn process(&mut self, ports: &mut Ports<'_>);
    /// false si el cliente ya no responde: el motor lo quita del grafo.
    fn alive(&self) -> bool { true }
}

/// Acceso de un cliente a los búferes de sus puertos durante un ciclo.
pub struct Ports<'a> {
    bufs: &'a mut BTreeMap<PortId, Vec<f32>>,
    graph: &'a Graph,
    client: ClientId,
    pub frames: usize,
    pub cycle: u64,
}

impl Ports<'_> {
    fn check(&self, p: PortId, dir: Direction) -> bool {
        self.graph.port(p).is_some_and(|q| q.client == self.client && q.dir == dir)
    }

    /// Muestras de una entrada del cliente (ya mezcladas).
    pub fn input(&self, p: PortId) -> &[f32] {
        assert!(self.check(p, Direction::Input), "no es una entrada de este cliente");
        &self.bufs[&p]
    }

    /// Búfer de una salida del cliente.
    pub fn output(&mut self, p: PortId) -> &mut [f32] {
        assert!(self.check(p, Direction::Output), "no es una salida de este cliente");
        self.bufs.get_mut(&p).unwrap()
    }

    /// Una entrada y una salida a la vez (procesado in -> out).
    pub fn io(&mut self, inp: PortId, out: PortId, f: impl FnOnce(&[f32], &mut [f32])) {
        assert!(self.check(inp, Direction::Input) && self.check(out, Direction::Output));
        let src = std::mem::take(self.bufs.get_mut(&inp).unwrap());
        f(&src, self.bufs.get_mut(&out).unwrap());
        *self.bufs.get_mut(&inp).unwrap() = src;
    }
}

/// Estadísticas del servidor.
#[derive(Clone, Copy, Debug, Default)]
pub struct Stats {
    pub cycles: u64,
    /// Periodos perdidos (xruns) en total.
    pub missed: u64,
    /// Clientes quitados por no responder.
    pub removed: u64,
}

pub struct Engine<B: Backend> {
    backend: B,
    format: Format,
    graph: Graph,
    procs: BTreeMap<ClientId, Box<dyn Process>>,
    bufs: BTreeMap<PortId, Vec<f32>>,
    stats: Stats,
    running: bool,
}

impl<B: Backend> Engine<B> {
    pub fn new(backend: B) -> Engine<B> {
        let format = backend.format();
        let graph = Graph::new(backend.capture_channels(), backend.playback_channels());
        let mut e = Engine {
            backend, format, graph, procs: BTreeMap::new(), bufs: BTreeMap::new(),
            stats: Stats::default(), running: false,
        };
        e.sync_buffers();
        e
    }

    pub fn format(&self) -> Format { self.format }
    pub fn graph(&self) -> &Graph { &self.graph }
    pub fn stats(&self) -> Stats { self.stats }
    pub fn backend(&self) -> &B { &self.backend }

    /// Un búfer por puerto, siempre de `period` muestras.
    fn sync_buffers(&mut self) {
        let n = self.format.period as usize;
        self.bufs.retain(|p, _| self.graph.port(*p).is_some());
        for p in self.graph.ports() {
            self.bufs.entry(p.id).or_insert_with(|| vec![0.0; n]);
        }
    }

    //-------------------------------------------------------------------------------//
    // Gestión del grafo                                                             //
    //-------------------------------------------------------------------------------//

    pub fn add_client(&mut self, name: &str, proc_: Box<dyn Process>) -> Result<ClientId> {
        let id = self.graph.add_client(name)?;
        self.procs.insert(id, proc_);
        Ok(id)
    }

    /// Añade un cliente cuyo código necesita conocer sus puertos: primero se crea el
    /// cliente y sus puertos, y luego se construye el objeto con sus ids.
    pub fn add_client_with<P: Process + 'static>(
        &mut self,
        name: &str,
        ports: &[(&str, Direction)],
        make: impl FnOnce(&[PortId]) -> P,
    ) -> Result<ClientId> {
        let id = self.graph.add_client(name)?;
        let mut ids = Vec::with_capacity(ports.len());
        for &(pname, dir) in ports {
            match self.graph.add_port(id, pname, dir) {
                Ok(p) => ids.push(p),
                Err(e) => {
                    let _ = self.graph.remove_client(id);
                    return Err(e);
                }
            }
        }
        self.procs.insert(id, Box::new(make(&ids)));
        self.sync_buffers();
        Ok(id)
    }

    pub fn remove_client(&mut self, id: ClientId) -> Result<()> {
        self.graph.remove_client(id)?;
        self.procs.remove(&id);
        self.sync_buffers();
        Ok(())
    }

    pub fn add_port(&mut self, client: ClientId, name: &str, dir: Direction) -> Result<PortId> {
        let p = self.graph.add_port(client, name, dir)?;
        self.sync_buffers();
        Ok(p)
    }

    /// Conecta por nombre completo: connect("sine:out", "system:playback_1").
    pub fn connect(&mut self, src: &str, dst: &str) -> Result<()> {
        let s = self.graph.find_port(src).ok_or(Error::NotFound)?;
        let d = self.graph.find_port(dst).ok_or(Error::NotFound)?;
        self.graph.connect(s, d)
    }

    pub fn disconnect(&mut self, src: &str, dst: &str) -> Result<()> {
        let s = self.graph.find_port(src).ok_or(Error::NotFound)?;
        let d = self.graph.find_port(dst).ok_or(Error::NotFound)?;
        self.graph.disconnect(s, d)
    }

    //-------------------------------------------------------------------------------//
    // Ciclo                                                                         //
    //-------------------------------------------------------------------------------//

    pub fn start(&mut self) -> Result<()> {
        self.backend.start()?;
        self.running = true;
        Ok(())
    }

    pub fn stop(&mut self) -> Result<()> {
        self.running = false;
        self.backend.stop()
    }

    /// Suma en el búfer de `dst` las salidas conectadas a él.
    fn mix_into(&mut self, dst: PortId) {
        let srcs: Vec<PortId> = self.graph.sources_of(dst).collect();
        let mut acc = std::mem::take(self.bufs.get_mut(&dst).unwrap());
        acc.fill(0.0);
        for s in srcs {
            for (a, x) in acc.iter_mut().zip(&self.bufs[&s]) {
                *a += *x;
            }
        }
        *self.bufs.get_mut(&dst).unwrap() = acc;
    }

    /// Ejecuta un ciclo completo.
    pub fn cycle(&mut self) -> Result<Wakeup> {
        if !self.running {
            return Err(Error::Backend("el servidor no está en marcha".into()));
        }
        let w = self.backend.wait()?;
        self.stats.missed += w.missed;

        // 2. Captura.
        let capture: Vec<PortId> = self.system_ports(Direction::Output);
        {
            let mut taken: Vec<Vec<f32>> =
                capture.iter().map(|p| std::mem::take(self.bufs.get_mut(p).unwrap())).collect();
            let mut refs: Vec<&mut [f32]> = taken.iter_mut().map(|v| v.as_mut_slice()).collect();
            let r = self.backend.read(&mut refs);
            for (p, v) in capture.iter().zip(taken) {
                *self.bufs.get_mut(p).unwrap() = v;
            }
            r?;
        }

        // 3. Clientes en orden.
        let order = self.graph.order().to_vec();
        for c in order {
            let inputs: Vec<PortId> = self.graph.ports_of(c)
                .filter(|p| p.dir == Direction::Input).map(|p| p.id).collect();
            for p in inputs {
                self.mix_into(p);
            }
            if let Some(proc_) = self.procs.get_mut(&c) {
                let mut ports = Ports {
                    bufs: &mut self.bufs, graph: &self.graph, client: c,
                    frames: self.format.period as usize, cycle: w.cycle,
                };
                proc_.process(&mut ports);
            }
        }

        // 4 y 5. Reproducción.
        let playback: Vec<PortId> = self.system_ports(Direction::Input);
        for &p in &playback {
            self.mix_into(p);
        }
        let refs: Vec<&[f32]> = playback.iter().map(|p| self.bufs[p].as_slice()).collect();
        self.backend.write(&refs)?;

        // Clientes que han dejado de responder.
        let dead: Vec<ClientId> = self.procs.iter().filter(|(_, p)| !p.alive())
            .map(|(&c, _)| c).collect();
        for c in dead {
            let _ = self.remove_client(c);
            self.stats.removed += 1;
        }

        self.stats.cycles += 1;
        Ok(w)
    }

    fn system_ports(&self, dir: Direction) -> Vec<PortId> {
        self.graph.ports_of(SYSTEM).filter(|p| p.dir == dir).map(|p| p.id).collect()
    }
}
