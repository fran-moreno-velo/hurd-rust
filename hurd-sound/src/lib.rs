//===================================================================================//
// hurd-sound: servidor de sonido para GNU/Hurd con el modelo de JACK                //
//===================================================================================//
//
// El servidor marca el ritmo: en cada periodo despierta a los clientes en orden
// topológico, cada uno procesa `period` muestras en sus puertos, y el servidor
// mezcla y entrega el resultado al backend.
//
// Paso 1 (este código): núcleo sin IPC ni hardware.
//   - graph:   clientes, puertos, conexiones y orden de proceso.
//   - engine:  ciclo de proceso y mezcla.
//   - backend: interfaz con el dispositivo; NullBackend (marca el ritmo con el
//              reloj) y WavBackend (escribe un fichero, sin esperar: "freewheel").
// Paso 2: clientes en otras tareas (memoria compartida + despertares Mach).
// Paso 3: driver en modo usuario (AC'97 en QEMU) como backend.

pub mod backend;
pub mod engine;
pub mod graph;
pub mod remote;
pub mod segment;
pub mod signal;

/// Formato de audio del servidor.  Como en JACK, todos los puertos son mono y
/// transportan muestras f32 en [-1, 1]; la frecuencia y el periodo son globales.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Format {
    /// Frecuencia de muestreo (Hz).
    pub rate: u32,
    /// Muestras por periodo (por puerto).
    pub period: u32,
}

impl Format {
    /// Duración de un periodo en nanosegundos.
    pub fn period_ns(&self) -> u64 {
        self.period as u64 * 1_000_000_000 / self.rate as u64
    }
}

/// Errores del núcleo.
#[derive(Debug)]
pub enum Error {
    /// El nombre ya existe (cliente o puerto).
    Exists(String),
    /// No existe el cliente, el puerto o la conexión.
    NotFound,
    /// La conexión no va de una salida a una entrada.
    BadDirection,
    /// La conexión cerraría un ciclo en el grafo.
    Cycle,
    /// Error del backend (E/S, dispositivo...).
    Backend(String),
    /// El otro extremo (cliente o servidor remoto) ha desaparecido.
    Disconnected,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Exists(n) => write!(f, "ya existe: {n}"),
            Error::NotFound => write!(f, "no existe"),
            Error::BadDirection => write!(f, "la conexión debe ir de una salida a una entrada"),
            Error::Cycle => write!(f, "la conexión cerraría un ciclo"),
            Error::Backend(m) => write!(f, "backend: {m}"),
            Error::Disconnected => write!(f, "el otro extremo ha desaparecido"),
        }
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;
