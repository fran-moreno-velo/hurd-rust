//===================================================================================//
// graph: clientes, puertos, conexiones y orden de proceso                           //
//===================================================================================//
//
// Como en JACK:
//  - Un puerto pertenece a un cliente y es de entrada o de salida (visto desde el
//    cliente: una salida produce muestras, una entrada las consume).
//  - Una conexión va de una salida a una entrada.  Una entrada puede recibir varias
//    conexiones: el servidor las suma (mezcla).
//  - El cliente "system" representa al dispositivo: sus salidas son la captura
//    (system:capture_N) y sus entradas la reproducción (system:playback_N).
//  - Los clientes se procesan en orden topológico: si A alimenta a B, A va antes.
//    "system" no entra en el orden: la captura se lee antes de procesar a nadie y
//    la reproducción se escribe después de todos.

use std::collections::{BTreeMap, BTreeSet};
use crate::{Error, Result};

pub type ClientId = u32;
pub type PortId = u32;

/// El cliente que representa al dispositivo.
pub const SYSTEM: ClientId = 0;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    /// El cliente consume muestras de este puerto.
    Input,
    /// El cliente produce muestras en este puerto.
    Output,
}

#[derive(Clone, Debug)]
pub struct Client {
    pub id: ClientId,
    pub name: String,
}

#[derive(Clone, Debug)]
pub struct Port {
    pub id: PortId,
    pub client: ClientId,
    /// Nombre corto (sin el prefijo "cliente:").
    pub name: String,
    pub dir: Direction,
}

#[derive(Debug, Default)]
pub struct Graph {
    clients: BTreeMap<ClientId, Client>,
    ports: BTreeMap<PortId, Port>,
    /// (salida, entrada)
    conns: BTreeSet<(PortId, PortId)>,
    next_client: ClientId,
    next_port: PortId,
    /// Orden de proceso de los clientes (sin "system"), recalculado en cada cambio.
    order: Vec<ClientId>,
}

impl Graph {
    /// Grafo con el cliente "system" y sus puertos de captura y reproducción.
    pub fn new(capture: usize, playback: usize) -> Graph {
        let mut g = Graph { next_client: SYSTEM + 1, next_port: 1, ..Default::default() };
        g.clients.insert(SYSTEM, Client { id: SYSTEM, name: "system".into() });
        for i in 1..=capture {
            g.insert_port(SYSTEM, format!("capture_{i}"), Direction::Output);
        }
        for i in 1..=playback {
            g.insert_port(SYSTEM, format!("playback_{i}"), Direction::Input);
        }
        g
    }

    //-------------------------------------------------------------------------------//
    // Clientes                                                                      //
    //-------------------------------------------------------------------------------//

    pub fn add_client(&mut self, name: &str) -> Result<ClientId> {
        if name.is_empty() || name.contains(':') {
            return Err(Error::NotFound);
        }
        if self.clients.values().any(|c| c.name == name) {
            return Err(Error::Exists(name.into()));
        }
        let id = self.next_client;
        self.next_client += 1;
        self.clients.insert(id, Client { id, name: name.into() });
        self.recompute_order().expect("un cliente nuevo no puede crear ciclos");
        Ok(id)
    }

    /// Elimina el cliente, sus puertos y sus conexiones.
    pub fn remove_client(&mut self, id: ClientId) -> Result<()> {
        if id == SYSTEM || !self.clients.contains_key(&id) {
            return Err(Error::NotFound);
        }
        // Primero los puertos y sus conexiones: el cliente debe seguir existiendo
        // mientras se recalcula el orden.
        let ports: Vec<PortId> = self.ports_of(id).map(|p| p.id).collect();
        for p in ports {
            self.remove_port(p)?;
        }
        self.clients.remove(&id);
        self.recompute_order().expect("quitar un cliente no puede crear ciclos");
        Ok(())
    }

    pub fn client(&self, id: ClientId) -> Option<&Client> {
        self.clients.get(&id)
    }

    pub fn clients(&self) -> impl Iterator<Item = &Client> {
        self.clients.values()
    }

    //-------------------------------------------------------------------------------//
    // Puertos                                                                       //
    //-------------------------------------------------------------------------------//

    pub fn add_port(&mut self, client: ClientId, name: &str, dir: Direction) -> Result<PortId> {
        if client == SYSTEM || !self.clients.contains_key(&client) {
            return Err(Error::NotFound);
        }
        if name.is_empty() || name.contains(':') {
            return Err(Error::NotFound);
        }
        if self.ports_of(client).any(|p| p.name == name) {
            return Err(Error::Exists(name.into()));
        }
        Ok(self.insert_port(client, name.into(), dir))
    }

    fn insert_port(&mut self, client: ClientId, name: String, dir: Direction) -> PortId {
        let id = self.next_port;
        self.next_port += 1;
        self.ports.insert(id, Port { id, client, name, dir });
        id
    }

    /// Elimina el puerto y sus conexiones.
    pub fn remove_port(&mut self, id: PortId) -> Result<()> {
        let port = self.ports.get(&id).ok_or(Error::NotFound)?;
        if port.client == SYSTEM {
            return Err(Error::NotFound);
        }
        self.ports.remove(&id);
        self.conns.retain(|&(a, b)| a != id && b != id);
        self.recompute_order().expect("quitar un puerto no puede crear ciclos");
        Ok(())
    }

    pub fn port(&self, id: PortId) -> Option<&Port> {
        self.ports.get(&id)
    }

    pub fn ports(&self) -> impl Iterator<Item = &Port> {
        self.ports.values()
    }

    pub fn ports_of(&self, client: ClientId) -> impl Iterator<Item = &Port> {
        self.ports.values().filter(move |p| p.client == client)
    }

    /// Nombre completo "cliente:puerto".
    pub fn full_name(&self, id: PortId) -> Option<String> {
        let p = self.ports.get(&id)?;
        let c = self.clients.get(&p.client)?;
        Some(format!("{}:{}", c.name, p.name))
    }

    /// Busca un puerto por su nombre completo "cliente:puerto".
    pub fn find_port(&self, full: &str) -> Option<PortId> {
        let (cname, pname) = full.split_once(':')?;
        let c = self.clients.values().find(|c| c.name == cname)?;
        self.ports_of(c.id).find(|p| p.name == pname).map(|p| p.id)
    }

    //-------------------------------------------------------------------------------//
    // Conexiones                                                                    //
    //-------------------------------------------------------------------------------//

    /// Conecta la salida `src` con la entrada `dst`.  Conectar dos veces no es error.
    pub fn connect(&mut self, src: PortId, dst: PortId) -> Result<()> {
        let s = self.ports.get(&src).ok_or(Error::NotFound)?;
        let d = self.ports.get(&dst).ok_or(Error::NotFound)?;
        if s.dir != Direction::Output || d.dir != Direction::Input {
            return Err(Error::BadDirection);
        }
        if !self.conns.insert((src, dst)) {
            return Ok(());
        }
        if self.recompute_order().is_err() {
            self.conns.remove(&(src, dst));
            self.recompute_order().expect("el grafo anterior no tenía ciclos");
            return Err(Error::Cycle);
        }
        Ok(())
    }

    pub fn disconnect(&mut self, src: PortId, dst: PortId) -> Result<()> {
        if !self.conns.remove(&(src, dst)) {
            return Err(Error::NotFound);
        }
        self.recompute_order().expect("quitar una conexión no puede crear ciclos");
        Ok(())
    }

    pub fn connections(&self) -> impl Iterator<Item = (PortId, PortId)> + '_ {
        self.conns.iter().copied()
    }

    /// Salidas conectadas a la entrada `dst`.
    pub fn sources_of(&self, dst: PortId) -> impl Iterator<Item = PortId> + '_ {
        self.conns.iter().filter(move |&&(_, b)| b == dst).map(|&(a, _)| a)
    }

    //-------------------------------------------------------------------------------//
    // Orden de proceso                                                              //
    //-------------------------------------------------------------------------------//

    /// Clientes (sin "system") en el orden en que deben procesarse.
    pub fn order(&self) -> &[ClientId] {
        &self.order
    }

    /// Orden topológico de Kahn sobre las aristas entre clientes (sin "system"),
    /// desempatando por id para que el orden sea estable.
    fn recompute_order(&mut self) -> std::result::Result<(), ()> {
        let nodes: Vec<ClientId> = self.clients.keys().copied().filter(|&c| c != SYSTEM).collect();
        let mut edges: BTreeSet<(ClientId, ClientId)> = BTreeSet::new();
        for &(a, b) in &self.conns {
            let (ca, cb) = (self.ports[&a].client, self.ports[&b].client);
            if ca != SYSTEM && cb != SYSTEM {
                if ca == cb {
                    return Err(()); // un cliente que se alimenta a sí mismo
                }
                edges.insert((ca, cb));
            }
        }
        let mut indeg: BTreeMap<ClientId, usize> = nodes.iter().map(|&n| (n, 0)).collect();
        for &(_, b) in &edges {
            *indeg.get_mut(&b).unwrap() += 1;
        }
        let mut ready: BTreeSet<ClientId> =
            indeg.iter().filter(|&(_, &d)| d == 0).map(|(&n, _)| n).collect();
        let mut order = Vec::with_capacity(nodes.len());
        while let Some(n) = ready.pop_first() {
            order.push(n);
            for &(_, b) in edges.iter().filter(|&&(a, _)| a == n) {
                let d = indeg.get_mut(&b).unwrap();
                *d -= 1;
                if *d == 0 {
                    ready.insert(b);
                }
            }
        }
        if order.len() != nodes.len() {
            return Err(());
        }
        self.order = order;
        Ok(())
    }
}
