//! Genera dos segundos de un La (440 Hz) en estéreo a través del grafo y lo
//! guarda en sine.wav:   cargo run --example sine_wav
use hurd_sound::backend::WavBackend;
use hurd_sound::engine::{Engine, Ports, Process};
use hurd_sound::graph::{Direction, PortId};
use hurd_sound::Format;

struct Sine { out: PortId, phase: f32, step: f32 }

impl Process for Sine {
    fn process(&mut self, p: &mut Ports<'_>) {
        for s in p.output(self.out) {
            *s = 0.3 * self.phase.sin();
            self.phase = (self.phase + self.step) % std::f32::consts::TAU;
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let fmt = Format { rate: 48_000, period: 256 };
    let mut e = Engine::new(WavBackend::create("sine.wav".as_ref(), fmt, 2)?);
    let step = std::f32::consts::TAU * 440.0 / fmt.rate as f32;
    e.add_client_with("sine", &[("out", Direction::Output)], |p| Sine { out: p[0], phase: 0.0, step })?;
    e.connect("sine:out", "system:playback_1")?;
    e.connect("sine:out", "system:playback_2")?;
    e.start()?;
    for _ in 0..(2 * fmt.rate / fmt.period) {
        e.cycle()?;
    }
    e.stop()?;
    println!("sine.wav: {} muestras por canal", e.backend().frames_written());
    Ok(())
}
