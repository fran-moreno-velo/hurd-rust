use hurd_sound::backend::{Backend, NullBackend, WavBackend};
use hurd_sound::engine::{Engine, Ports, Process};
use hurd_sound::graph::{Direction, Graph, PortId};
use hurd_sound::{Error, Format};

const FMT: Format = Format { rate: 48_000, period: 64 };

/// Escribe una constante en su salida.
struct Const { out: PortId, value: f32 }
impl Process for Const {
    fn process(&mut self, p: &mut Ports<'_>) { p.output(self.out).fill(self.value); }
}

/// Multiplica su entrada por una ganancia.
struct Gain { inp: PortId, out: PortId, g: f32 }
impl Process for Gain {
    fn process(&mut self, p: &mut Ports<'_>) {
        let g = self.g;
        p.io(self.inp, self.out, |i, o| for (o, i) in o.iter_mut().zip(i) { *o = i * g });
    }
}

fn wav_samples(path: &std::path::Path) -> (Vec<u8>, Vec<i16>) {
    let bytes = std::fs::read(path).unwrap();
    let data = bytes[44..].chunks(2).map(|c| i16::from_le_bytes([c[0], c[1]])).collect();
    (bytes[..44].to_vec(), data)
}

fn tmp(name: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("hurd-sound-{}-{name}.wav", std::process::id()))
}

#[test]
fn connections_go_from_output_to_input() {
    let mut g = Graph::new(2, 2);
    let a = g.add_client("a").unwrap();
    let out = g.add_port(a, "out", Direction::Output).unwrap();
    let inp = g.add_port(a, "in", Direction::Input).unwrap();
    let pb = g.find_port("system:playback_1").unwrap();
    assert!(matches!(g.connect(inp, pb), Err(Error::BadDirection)));
    assert!(matches!(g.connect(out, inp), Err(Error::Cycle)), "un cliente no puede alimentarse");
    g.connect(out, pb).unwrap();
    g.connect(out, pb).unwrap(); // idempotente
    assert_eq!(g.connections().count(), 1);
    assert!(matches!(g.add_client("a"), Err(Error::Exists(_))));
}

#[test]
fn order_follows_connections_and_rejects_cycles() {
    let mut g = Graph::new(0, 1);
    // Se registran al revés del orden en que deben procesarse.
    let b = g.add_client("b").unwrap();
    let a = g.add_client("a").unwrap();
    let b_in = g.add_port(b, "in", Direction::Input).unwrap();
    let b_out = g.add_port(b, "out", Direction::Output).unwrap();
    let a_in = g.add_port(a, "in", Direction::Input).unwrap();
    let a_out = g.add_port(a, "out", Direction::Output).unwrap();
    g.connect(a_out, b_in).unwrap();
    assert_eq!(g.order(), &[a, b]);
    assert!(matches!(g.connect(b_out, a_in), Err(Error::Cycle)));
    assert_eq!(g.order(), &[a, b], "un connect rechazado no cambia el grafo");
    g.remove_client(a).unwrap();
    assert_eq!(g.order(), &[b]);
    assert_eq!(g.connections().count(), 0);
}

#[test]
fn inputs_are_mixed_and_chains_run_in_order() {
    let path = tmp("mix");
    let mut e = Engine::new(WavBackend::create(&path, FMT, 2).unwrap());
    e.add_client_with("c1", &[("out", Direction::Output)], |p| Const { out: p[0], value: 0.25 }).unwrap();
    e.add_client_with("c2", &[("out", Direction::Output)], |p| Const { out: p[0], value: 0.5 }).unwrap();
    // gain se registra antes de su fuente: el orden topológico lo corrige.
    e.add_client_with("gain", &[("in", Direction::Input), ("out", Direction::Output)],
                      |p| Gain { inp: p[0], out: p[1], g: 0.5 }).unwrap();
    e.add_client_with("src", &[("out", Direction::Output)], |p| Const { out: p[0], value: 0.8 }).unwrap();
    e.connect("c1:out", "system:playback_1").unwrap();
    e.connect("c2:out", "system:playback_1").unwrap();
    e.connect("src:out", "gain:in").unwrap();
    e.connect("gain:out", "system:playback_2").unwrap();
    e.start().unwrap();
    for _ in 0..10 { e.cycle().unwrap(); }
    e.stop().unwrap();
    assert_eq!(e.backend().frames_written(), 640);

    let (hdr, s) = wav_samples(&path);
    assert_eq!(&hdr[0..4], b"RIFF");
    assert_eq!(u32::from_le_bytes(hdr[40..44].try_into().unwrap()), 640 * 2 * 2);
    assert_eq!(s.len(), 640 * 2);
    let q = |x: f32| (x * i16::MAX as f32).round() as i16;
    assert!(s.chunks(2).all(|f| f[0] == q(0.75) && f[1] == q(0.4)), "L = 0.25 + 0.5, R = 0.8 · 0.5");
    let _ = std::fs::remove_file(path);
}

#[test]
fn clipping_is_counted() {
    let path = tmp("clip");
    let mut e = Engine::new(WavBackend::create(&path, FMT, 1).unwrap());
    for n in ["a", "b"] {
        e.add_client_with(n, &[("out", Direction::Output)], |p| Const { out: p[0], value: 0.75 }).unwrap();
        e.connect(&format!("{n}:out"), "system:playback_1").unwrap();
    }
    e.start().unwrap();
    e.cycle().unwrap();
    assert_eq!(e.backend().clipped, 64);
    let _ = std::fs::remove_file(path);
}

#[test]
fn null_backend_paces_by_the_clock() {
    let fmt = Format { rate: 48_000, period: 480 }; // 10 ms
    let mut b = NullBackend::new(fmt, 0, 2);
    b.start().unwrap();
    let t0 = std::time::Instant::now();
    let mut last = 0;
    for _ in 0..20 { last = b.wait().unwrap().cycle; }
    let el = t0.elapsed().as_millis();
    assert_eq!(last, 19);
    // 20 periodos empiezan en t = 0..19·10 ms: unos 190 ms.
    assert!((180..400).contains(&el), "transcurridos {el} ms");
}
