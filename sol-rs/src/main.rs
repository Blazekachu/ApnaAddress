use ed25519_dalek::SigningKey;
use rand::{rngs::StdRng, RngCore, SeedableRng};
use std::env;
use std::sync::{atomic::{AtomicBool, AtomicU64, Ordering}, mpsc, Arc};
use std::thread;
use std::time::{Duration, Instant};

struct ResultHit { address: String, seed: [u8; 32], attempts: u64 }

fn arg_value(args: &[String], name: &str) -> Option<String> {
    args.windows(2).find(|w| w[0] == name).map(|w| w[1].clone())
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let prefix = arg_value(&args, "--prefix").unwrap_or_default();
    let suffix = arg_value(&args, "--suffix").unwrap_or_default();
    let threads: usize = arg_value(&args, "--threads").and_then(|s| s.parse().ok()).unwrap_or_else(|| std::thread::available_parallelism().map(|n| n.get()).unwrap_or(8));
    let duration = arg_value(&args, "--duration").and_then(|s| parse_duration(&s));
    if prefix.is_empty() && suffix.is_empty() {
        eprintln!("Error: at least one of --prefix or --suffix required");
        std::process::exit(1);
    }
    println!("\nSearching for SOL address with prefix {:?}...", prefix);
    println!("Using {} Rust worker threads", threads);
    println!("Press Ctrl+C to stop.\n");

    let stop = Arc::new(AtomicBool::new(false));
    let attempts = Arc::new(AtomicU64::new(0));
    let (tx, rx) = mpsc::channel::<ResultHit>();
    let start = Instant::now();

    for id in 0..threads {
        let stop = stop.clone();
        let attempts = attempts.clone();
        let tx = tx.clone();
        let prefix = prefix.clone();
        let suffix = suffix.clone();
        thread::spawn(move || {
            let mut seed_rng = [0u8; 32];
            seed_rng[..8].copy_from_slice(&(id as u64).to_le_bytes());
            seed_rng[8..16].copy_from_slice(&(Instant::now().elapsed().as_nanos() as u64).to_le_bytes());
            let mut rng = StdRng::from_seed(seed_rng);
            let mut local = 0u64;
            loop {
                if local & 1023 == 0 && stop.load(Ordering::Relaxed) { break; }
                let mut seed = [0u8; 32];
                rng.fill_bytes(&mut seed);
                let signing = SigningKey::from_bytes(&seed);
                let verify = signing.verifying_key();
                let pubkey = verify.to_bytes();
                let address = bs58::encode(pubkey).into_string();
                local += 1;
                if local >= 16384 { attempts.fetch_add(local, Ordering::Relaxed); local = 0; }
                if (prefix.is_empty() || address.starts_with(&prefix)) && (suffix.is_empty() || address.ends_with(&suffix)) {
                    let total = attempts.fetch_add(local, Ordering::Relaxed) + local;
                    let _ = tx.send(ResultHit { address, seed, attempts: total });
                    stop.store(true, Ordering::Relaxed);
                    break;
                }
            }
            if local > 0 { attempts.fetch_add(local, Ordering::Relaxed); }
        });
    }
    drop(tx);

    loop {
        if let Some(d) = duration {
            if start.elapsed() >= d {
                stop.store(true, Ordering::Relaxed);
                thread::sleep(Duration::from_millis(100));
                let n = attempts.load(Ordering::Relaxed);
                let secs = start.elapsed().as_secs_f64();
                println!("BENCH attempts={} seconds={:.3} keys_per_sec={:.0} threads={}", n, secs, n as f64 / secs, threads);
                return;
            }
        }
        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(hit) => {
                let secs = start.elapsed().as_secs_f64();
                println!("MATCH FOUND!\nAddress      : {}\nPrivate Seed : {}\nAttempts     : {}\nTime         : {:.1}s\nSpeed        : {:.0} keys/sec", hit.address, hex_seed(&hit.seed), hit.attempts, secs, hit.attempts as f64 / secs);
                return;
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(_) => return,
        }
    }
}

fn parse_duration(s: &str) -> Option<Duration> {
    s.strip_suffix('s').and_then(|n| n.parse::<f64>().ok()).map(Duration::from_secs_f64)
}
fn hex_seed(seed: &[u8;32]) -> String { seed.iter().map(|b| format!("{:02x}", b)).collect() }
