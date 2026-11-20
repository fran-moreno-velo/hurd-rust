//===================================================================================//
// backend: interfaz con el dispositivo                                             //
//===================================================================================//
//
// El backend es quien marca el ritmo: `wait` vuelve cuando el dispositivo necesita
// el siguiente periodo.  Con hardware, eso lo señala la interrupción del DMA; sin
// hardware, NullBackend usa el reloj y WavBackend no espera (modo "freewheel",
// útil para pruebas deterministas y para renderizar más rápido que en tiempo real).

use std::fs::File;
use std::io::{BufWriter, Seek, SeekFrom, Write};
use std::path::Path;
use std::time::{Duration, Instant};

use crate::{Error, Format, Result};

/// Resultado de esperar al siguiente periodo.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Wakeup {
    /// Número de periodo (0, 1, 2...) desde start().
    pub cycle: u64,
    /// Periodos perdidos desde la última espera (xrun: el servidor llegó tarde).
    pub missed: u64,
}

pub trait Backend {
    fn format(&self) -> Format;
    fn capture_channels(&self) -> usize;
    fn playback_channels(&self) -> usize;

    fn start(&mut self) -> Result<()>;
    /// Espera hasta que el dispositivo necesite el siguiente periodo.
    fn wait(&mut self) -> Result<Wakeup>;
    /// Llena `capture` (un búfer de `period` muestras por canal).
    fn read(&mut self, capture: &mut [&mut [f32]]) -> Result<()>;
    /// Entrega `playback` (un búfer de `period` muestras por canal).
    fn write(&mut self, playback: &[&[f32]]) -> Result<()>;
    fn stop(&mut self) -> Result<()>;
}

//-----------------------------------------------------------------------------------//
// NullBackend: descarta el audio y marca el ritmo con el reloj                      //
//-----------------------------------------------------------------------------------//
//
// En GNU Mach el temporizador del núcleo avanza por ticks (históricamente 100 Hz),
// así que un sleep no puede despertar con más resolución que un tick.  Con periodos
// más cortos que un tick el NullBackend no se retrasa: devuelve varios periodos
// seguidos tras cada despertar (las deadlines se calculan desde el inicio, no desde
// el último despertar, para que el error no se acumule).

pub struct NullBackend {
    format: Format,
    capture: usize,
    playback: usize,
    start: Option<Instant>,
    cycle: u64,
}

impl NullBackend {
    pub fn new(format: Format, capture: usize, playback: usize) -> NullBackend {
        NullBackend { format, capture, playback, start: None, cycle: 0 }
    }

    fn deadline(&self, cycle: u64) -> Duration {
        Duration::from_nanos(cycle.saturating_mul(self.format.period_ns()))
    }
}

impl Backend for NullBackend {
    fn format(&self) -> Format { self.format }
    fn capture_channels(&self) -> usize { self.capture }
    fn playback_channels(&self) -> usize { self.playback }

    fn start(&mut self) -> Result<()> {
        self.start = Some(Instant::now());
        self.cycle = 0;
        Ok(())
    }

    fn wait(&mut self) -> Result<Wakeup> {
        let start = self.start.ok_or_else(|| Error::Backend("no iniciado".into()))?;
        // El periodo `cycle` se entrega cuando termina el anterior: en t = cycle·T.
        let target = start + self.deadline(self.cycle);
        let now = Instant::now();
        if target > now {
            std::thread::sleep(target - now);
        }
        // Si vamos más de un periodo tarde, se pierden los periodos intermedios.
        let elapsed = start.elapsed();
        let period = self.format.period_ns().max(1);
        let due = elapsed.as_nanos() as u64 / period;
        let missed = due.saturating_sub(self.cycle + 1);
        self.cycle += missed;
        let w = Wakeup { cycle: self.cycle, missed };
        self.cycle += 1;
        Ok(w)
    }

    fn read(&mut self, capture: &mut [&mut [f32]]) -> Result<()> {
        for ch in capture.iter_mut() {
            ch.fill(0.0);
        }
        Ok(())
    }

    fn write(&mut self, _playback: &[&[f32]]) -> Result<()> { Ok(()) }

    fn stop(&mut self) -> Result<()> {
        self.start = None;
        Ok(())
    }
}

//-----------------------------------------------------------------------------------//
// WavBackend: escribe la reproducción en un WAV PCM de 16 bits, sin esperar         //
//-----------------------------------------------------------------------------------//

pub struct WavBackend {
    format: Format,
    channels: usize,
    out: Option<BufWriter<File>>,
    frames: u64,
    cycle: u64,
    /// Muestras que hubo que recortar a [-1, 1] (saturación).
    pub clipped: u64,
}

impl WavBackend {
    pub fn create(path: &Path, format: Format, channels: usize) -> Result<WavBackend> {
        assert!(channels > 0 && channels <= u16::MAX as usize);
        let f = File::create(path).map_err(|e| Error::Backend(e.to_string()))?;
        let mut out = BufWriter::new(f);
        write_wav_header(&mut out, format.rate, channels as u16, 0).map_err(io)?;
        Ok(WavBackend { format, channels, out: Some(out), frames: 0, cycle: 0, clipped: 0 })
    }

    pub fn frames_written(&self) -> u64 { self.frames }

    fn finish(&mut self) -> std::io::Result<()> {
        if let Some(mut out) = self.out.take() {
            let data = self.frames * self.channels as u64 * 2;
            out.seek(SeekFrom::Start(0))?;
            write_wav_header(&mut out, self.format.rate, self.channels as u16, data as u32)?;
            out.flush()?;
        }
        Ok(())
    }
}

fn io(e: std::io::Error) -> Error { Error::Backend(e.to_string()) }

fn write_wav_header(w: &mut impl Write, rate: u32, channels: u16, data_len: u32) -> std::io::Result<()> {
    let block = channels as u32 * 2;
    w.write_all(b"RIFF")?;
    w.write_all(&(36 + data_len).to_le_bytes())?;
    w.write_all(b"WAVEfmt ")?;
    w.write_all(&16u32.to_le_bytes())?;
    w.write_all(&1u16.to_le_bytes())?;          // PCM
    w.write_all(&channels.to_le_bytes())?;
    w.write_all(&rate.to_le_bytes())?;
    w.write_all(&(rate * block).to_le_bytes())?;
    w.write_all(&(block as u16).to_le_bytes())?;
    w.write_all(&16u16.to_le_bytes())?;         // bits por muestra
    w.write_all(b"data")?;
    w.write_all(&data_len.to_le_bytes())
}

impl Backend for WavBackend {
    fn format(&self) -> Format { self.format }
    fn capture_channels(&self) -> usize { 0 }
    fn playback_channels(&self) -> usize { self.channels }

    fn start(&mut self) -> Result<()> {
        self.cycle = 0;
        Ok(())
    }

    fn wait(&mut self) -> Result<Wakeup> {
        let w = Wakeup { cycle: self.cycle, missed: 0 };
        self.cycle += 1;
        Ok(w)
    }

    fn read(&mut self, _capture: &mut [&mut [f32]]) -> Result<()> { Ok(()) }

    fn write(&mut self, playback: &[&[f32]]) -> Result<()> {
        let out = self.out.as_mut().ok_or_else(|| Error::Backend("cerrado".into()))?;
        let n = self.format.period as usize;
        let mut buf = Vec::with_capacity(n * self.channels * 2);
        for i in 0..n {
            for ch in playback.iter().take(self.channels) {
                let s = ch[i];
                let c = s.clamp(-1.0, 1.0);
                if c != s {
                    self.clipped += 1;
                }
                buf.extend_from_slice(&((c * i16::MAX as f32).round() as i16).to_le_bytes());
            }
        }
        out.write_all(&buf).map_err(io)?;
        self.frames += n as u64;
        Ok(())
    }

    fn stop(&mut self) -> Result<()> {
        self.finish().map_err(io)
    }
}

impl Drop for WavBackend {
    fn drop(&mut self) {
        let _ = self.finish();
    }
}
