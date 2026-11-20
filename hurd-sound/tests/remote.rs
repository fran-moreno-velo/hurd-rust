use std::time::Duration;

use hurd_sound::backend::WavBackend;
use hurd_sound::engine::{Engine, Ports, Process};
use hurd_sound::graph::{Direction, PortId};
use hurd_sound::remote::{run_client, ClientPorts, RemoteClient, RemoteProcess, MAX_LATE};
use hurd_sound::segment::Segment;
use hurd_sound::signal::{channel, ClientSignal};
use hurd_sound::Format;

const FMT: Format = Format { rate: 48_000, period: 64 };

struct Const { out: PortId, value: f32 }
impl Process for Const {
    fn process(&mut self, p: &mut Ports<'_>) { p.output(self.out).fill(self.value); }
}

/// Cliente remoto: salida = entrada * 2.
struct Double;
impl RemoteProcess for Double {
    fn process(&mut self, p: &mut ClientPorts<'_>) {
        let x: Vec<f32> = p.input(0).to_vec();
        for (o, i) in p.output(1).iter_mut().zip(x) { *o = i * 2.0; }
    }
}

/// Cliente que nunca contesta.
struct Hung;
impl RemoteProcess for Hung {
    fn process(&mut self, _: &mut ClientPorts<'_>) { std::thread::sleep(Duration::from_secs(3600)); }
}

fn tmp(name: &str, ext: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("hurd-sound-{}-{name}.{ext}", std::process::id()))
}

/// Monta: const(0.25) -> remoto:in ; remoto:out -> system:playback_1
fn setup(name: &str, remote: impl RemoteProcess + Send + 'static, timeout: Duration)
         -> (Engine<WavBackend>, std::path::PathBuf, std::thread::JoinHandle<()>) {
    let wav = tmp(name, "wav");
    let segp = tmp(name, "seg");
    let ports = [("in", Direction::Input), ("out", Direction::Output)];
    let seg = Segment::create(&segp, FMT, &ports).unwrap();
    let (ssig, mut csig) = channel();

    let p2 = segp.clone();
    let mut remote = remote;
    let th = std::thread::spawn(move || {
        let seg = Segment::open(&p2).unwrap();
        let _ = run_client(&seg, &mut csig, &mut remote);
        let _ = csig.done();
    });

    let mut e = Engine::new(WavBackend::create(&wav, FMT, 1).unwrap());
    e.add_client_with("src", &[("out", Direction::Output)], |ids| Const { out: ids[0], value: 0.25 }).unwrap();
    e.add_client_with("rem", &ports, move |ids| {
        let mut r = RemoteClient::new(seg, ssig, ids.to_vec());
        r.set_timeout(timeout);
        r
    }).unwrap();
    e.connect("src:out", "rem:in").unwrap();
    e.connect("rem:out", "system:playback_1").unwrap();
    (e, wav, th)
}

fn samples(path: &std::path::Path) -> Vec<i16> {
    std::fs::read(path).unwrap()[44..].chunks(2).map(|c| i16::from_le_bytes([c[0], c[1]])).collect()
}

#[test]
fn remote_client_processes_through_segment() {
    let (mut e, wav, th) = setup("double", Double, Duration::from_secs(2));
    e.start().unwrap();
    for _ in 0..50 { e.cycle().unwrap(); }
    e.stop().unwrap();
    assert_eq!(e.stats().removed, 0);
    drop(e); // cierra el segmento: el cliente sale de run_client
    th.join().unwrap();

    let s = samples(&wav);
    assert_eq!(s.len(), 50 * 64);
    // 0.25 * 2 = 0.5 -> 16383 aprox.
    assert!(s.iter().all(|&v| (v - 16383).abs() <= 1), "primera muestra {}", s[0]);
    let _ = std::fs::remove_file(wav);
}

#[test]
fn hung_client_gives_silence_and_is_removed() {
    let (mut e, wav, _th) = setup("hung", Hung, Duration::from_millis(5));
    e.start().unwrap();
    for _ in 0..(MAX_LATE as usize + 4) { e.cycle().unwrap(); }
    e.stop().unwrap();
    assert_eq!(e.stats().removed, 1);
    assert!(e.graph().find_port("rem:out").is_none());
    let s = samples(&wav);
    assert!(s.iter().all(|&v| v == 0));
    let _ = std::fs::remove_file(wav);
    // El hilo colgado se abandona.
}
