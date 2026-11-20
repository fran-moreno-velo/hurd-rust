//===================================================================================//
// segment: memoria compartida entre el servidor y un cliente                        //
//===================================================================================//
//
// Un segmento por cliente: un fichero en un tmpfs (por defecto /tmp/hurd-sound;
// /tmp está en el disco y su pager podría escribir las páginas en cualquier
// momento) mapeado con MAP_SHARED en las dos tareas.
//
//   +------------------+  offset 0
//   | SegmentHeader    |  magic, versión, formato, contadores atómicos
//   | PortSlot[..]     |  nombre, dirección y offset del búfer de cada puerto
//   +------------------+  alineado a 64
//   | búfer puerto 0   |  `period` muestras f32
//   | búfer puerto 1   |
//   | ...              |
//   +------------------+
//
// Protocolo de un ciclo (los búferes nunca los tocan los dos a la vez):
//   servidor: escribe las entradas, guarda `cycle`, despierta al cliente
//   cliente:  lee entradas, escribe salidas, guarda `done = cycle`, avisa
//   servidor: si `done == cycle`, lee las salidas; si no (llegó tarde), silencio

use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use crate::graph::Direction;
use crate::{Error, Format, Result};

pub const MAGIC: u32 = u32::from_le_bytes(*b"HSND");
pub const VERSION: u32 = 1;
pub const MAX_PORTS: usize = 32;
pub const PORT_NAME_MAX: usize = 32;

/// Directorio por defecto de los segmentos (debe ser un tmpfs).
pub const DEFAULT_DIR: &str = "/tmp/hurd-sound";

#[repr(C)]
pub struct PortSlot {
    pub name: [u8; PORT_NAME_MAX],
    /// 0 = entrada, 1 = salida (vista desde el cliente).
    pub dir: u32,
    /// Offset del búfer desde el inicio del segmento.
    pub offset: u32,
}

#[repr(C)]
pub struct SegmentHeader {
    pub magic: u32,
    pub version: u32,
    pub rate: u32,
    pub period: u32,
    pub nports: u32,
    /// Lo pone el servidor al cerrar el segmento: el cliente debe terminar.
    pub shutdown: AtomicU32,
    /// Ciclo que el servidor ha pedido procesar.
    pub cycle: AtomicU64,
    /// Último ciclo que el cliente ha terminado.
    pub done: AtomicU64,
    /// Ciclos en los que el cliente llegó tarde (los cuenta el servidor).
    pub late: AtomicU64,
    pub ports: [PortSlot; MAX_PORTS],
}

const fn align64(x: usize) -> usize { (x + 63) & !63 }

pub struct Segment {
    ptr: *mut u8,
    len: usize,
    path: PathBuf,
    owner: bool,
    _file: File,
}

// El segmento es memoria compartida con otra tarea; el acceso a los búferes lo
// coordina el protocolo de arriba, y la cabecera usa atómicos.
unsafe impl Send for Segment {}

impl Segment {
    /// Tamaño necesario para `nports` puertos de `period` muestras.
    pub fn size_for(period: u32, nports: usize) -> usize {
        align64(size_of::<SegmentHeader>()) + nports * align64(period as usize * 4)
    }

    /// Crea el segmento (lado servidor).
    pub fn create(path: &Path, fmt: Format, ports: &[(&str, Direction)]) -> Result<Segment> {
        if ports.len() > MAX_PORTS {
            return Err(Error::Backend(format!("como máximo {MAX_PORTS} puertos")));
        }
        let len = Self::size_for(fmt.period, ports.len());
        let file = OpenOptions::new().read(true).write(true).create(true).truncate(true)
            .open(path).map_err(io)?;
        file.set_len(len as u64).map_err(io)?;
        let ptr = map(&file, len)?;
        let seg = Segment { ptr, len, path: path.into(), owner: true, _file: file };

        // SAFETY: el mapeo tiene `len` bytes, puestos a cero por set_len, y nadie
        // más lo ha abierto todavía.
        let h = unsafe { &mut *(seg.ptr as *mut SegmentHeader) };
        h.rate = fmt.rate;
        h.period = fmt.period;
        h.nports = ports.len() as u32;
        let mut off = align64(size_of::<SegmentHeader>());
        for (slot, (name, dir)) in h.ports.iter_mut().zip(ports) {
            let n = name.as_bytes();
            if n.len() >= PORT_NAME_MAX {
                return Err(Error::Backend(format!("nombre de puerto demasiado largo: {name}")));
            }
            slot.name[..n.len()].copy_from_slice(n);
            slot.dir = matches!(dir, Direction::Output) as u32;
            slot.offset = off as u32;
            off += align64(fmt.period as usize * 4);
        }
        h.version = VERSION;
        // La magia se escribe la última: un cliente que la ve tiene el resto.
        std::sync::atomic::fence(Ordering::Release);
        h.magic = MAGIC;
        Ok(seg)
    }

    /// Abre un segmento existente (lado cliente) y comprueba su cabecera.
    pub fn open(path: &Path) -> Result<Segment> {
        let file = OpenOptions::new().read(true).write(true).open(path).map_err(io)?;
        let len = file.metadata().map_err(io)?.len() as usize;
        if len < size_of::<SegmentHeader>() {
            return Err(Error::Backend("segmento demasiado pequeño".into()));
        }
        let ptr = map(&file, len)?;
        let seg = Segment { ptr, len, path: path.into(), owner: false, _file: file };
        let h = seg.header();
        std::sync::atomic::fence(Ordering::Acquire);
        if h.magic != MAGIC || h.version != VERSION || h.nports as usize > MAX_PORTS
            || Self::size_for(h.period, h.nports as usize) > len
        {
            return Err(Error::Backend("cabecera de segmento no válida".into()));
        }
        Ok(seg)
    }

    pub fn header(&self) -> &SegmentHeader {
        // SAFETY: el mapeo empieza por una SegmentHeader (comprobado en open/create).
        unsafe { &*(self.ptr as *const SegmentHeader) }
    }

    pub fn format(&self) -> Format {
        let h = self.header();
        Format { rate: h.rate, period: h.period }
    }

    pub fn nports(&self) -> usize { self.header().nports as usize }

    pub fn port_name(&self, i: usize) -> &str {
        let n = &self.header().ports[i].name;
        let end = n.iter().position(|&b| b == 0).unwrap_or(n.len());
        std::str::from_utf8(&n[..end]).unwrap_or("?")
    }

    pub fn port_dir(&self, i: usize) -> Direction {
        if self.header().ports[i].dir == 1 { Direction::Output } else { Direction::Input }
    }

    /// Búfer del puerto `i`.
    ///
    /// # Safety
    /// Quien llama debe respetar el protocolo del ciclo: el servidor solo toca
    /// las entradas antes de despertar al cliente y las salidas después de que
    /// termine; el cliente, solo entre el despertar y su aviso de fin.
    #[allow(clippy::mut_from_ref)]
    pub unsafe fn buffer(&self, i: usize) -> &mut [f32] {
        let h = self.header();
        assert!(i < h.nports as usize);
        let off = h.ports[i].offset as usize;
        let n = h.period as usize;
        assert!(off + n * 4 <= self.len);
        unsafe { std::slice::from_raw_parts_mut(self.ptr.add(off) as *mut f32, n) }
    }

    pub fn path(&self) -> &Path { &self.path }
}

impl Drop for Segment {
    fn drop(&mut self) {
        if self.owner {
            self.header().shutdown.store(1, Ordering::Release);
            let _ = std::fs::remove_file(&self.path);
        }
        // SAFETY: ptr/len vienen de nuestro mmap.
        unsafe { munmap(self.ptr as *mut std::ffi::c_void, self.len); }
    }
}

fn io(e: std::io::Error) -> Error { Error::Backend(e.to_string()) }

fn map(file: &File, len: usize) -> Result<*mut u8> {
    use std::os::fd::AsRawFd;
    // SAFETY: fd válido; el fichero tiene al menos `len` bytes.
    let p = unsafe {
        libc::mmap(std::ptr::null_mut(), len, libc::PROT_READ | libc::PROT_WRITE,
                   libc::MAP_SHARED, file.as_raw_fd(), 0)
    };
    if p == libc::MAP_FAILED {
        return Err(io(std::io::Error::last_os_error()));
    }
    Ok(p as *mut u8)
}

use libc::munmap;
