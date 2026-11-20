//! Prueba del timbre Mach en el Hurd: servidor y cliente remoto en dos hilos de la
//! misma tarea, comunicados por el segmento y por mensajes Mach.
//!
//!   cargo run --release --features hurd --example mach_pair [periodo] [ciclos]
//!
//! Cadena: const(0.25) -> rem:in ; rem:out (x2) -> system:playback_1 -> WAV.
//! Al final imprime ciclos tardíos y comprueba que todas las muestras valen 0,5.

use std::time::{Duration, Instant};

use hurd_sound::backend::WavBackend;
use hurd_sound::engine::{Engine, Ports, Process};
use hurd_sound::graph::{Direction, PortId};
use hurd_sound::remote::{run_client, ClientPorts, RemoteClient, RemoteProcess};
use hurd_sound::segment::{Segment, DEFAULT_DIR};
use hurd_sound::signal::mach;
use hurd_sound::Format;

struct Const { out: PortId }
impl Process for Const {
    fn process(&mut self, p: &mut Ports<'_>) { p.output(self.out).fill(0.25); }
}

struct Double;
impl RemoteProcess for Double {
    fn process(&mut self, p: &mut ClientPorts<'_>) {
        let x = p.input(0).to_vec();
        for (o, i) in p.output(1).iter_mut().zip(x) { *o = i * 2.0; }
    }
}

fn main() {
    let mut args = std::env::args().skip(1);
    let period: u32 = args.next().map(|s| s.parse().unwrap()).unwrap_or(1024);
    let cycles: usize = args.next().map(|s| s.parse().unwrap()).unwrap_or(1000);
    let fmt = Format { rate: 48_000, period };

    let segp = std::path::Path::new(DEFAULT_DIR).join(format!("mach-pair-{}", std::process::id()));
    let ports = [("in", Direction::Input), ("out", Direction::Output)];
    let seg = Segment::create(&segp, fmt, &ports).expect("crear segmento");
    let (ssig, mut csig) = mach::pair().expect("puertos Mach");

    let p2 = segp.clone();
    let th = std::thread::spawn(move || {
        let seg = Segment::open(&p2).expect("abrir segmento");
        run_client(&seg, &mut csig, &mut Double).expect("cliente");
    });

    let wav = std::env::temp_dir().join("mach_pair.wav");
    let mut e = Engine::new(WavBackend::create(&wav, fmt, 1).unwrap());
    e.add_client_with("src", &[("out", Direction::Output)], |ids| Const { out: ids[0] }).unwrap();
    e.add_client_with("rem", &ports, move |ids| {
        let mut r = RemoteClient::new(seg, ssig, ids.to_vec());
        // Holgado: aquí medimos la ida y vuelta, no el plazo.
        r.set_timeout(Duration::from_millis(100));
        r
    }).unwrap();
    e.connect("src:out", "rem:in").unwrap();
    e.connect("rem:out", "system:playback_1").unwrap();

    e.start().unwrap();
    let t0 = Instant::now();
    for _ in 0..cycles { e.cycle().unwrap(); }
    let dt = t0.elapsed();
    e.stop().unwrap();
    let st = e.stats();
    drop(e);
    th.join().unwrap();

    let bytes = std::fs::read(&wav).unwrap();
    let bad = bytes[44..].chunks(2).map(|c| i16::from_le_bytes([c[0], c[1]]))
        .filter(|&v| (v - 16383).abs() > 1).count();
    println!("periodo {period}, {cycles} ciclos en {dt:?} ({:?}/ciclo)", dt / cycles as u32);
    println!("clientes quitados: {}, muestras incorrectas: {bad}", st.removed);
    println!("{}", if bad == 0 && st.removed == 0 { "OK" } else { "FALLO" });
}
