use ed25519_dalek::SigningKey;
use rand::{rngs::StdRng, RngCore, SeedableRng};
use std::env;
use std::process;
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    mpsc, Arc,
};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const BASE58: &str = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

#[derive(Clone)]
struct Config {
    prefix: String,
    suffix: String,
    threads: usize,
    duration: Option<Duration>,
    quiet: bool,
}

struct ResultHit {
    address: String,
    seed: [u8; 32],
    keypair: String,
    attempts: u64,
}

fn main() {
    let config = parse_args().unwrap_or_else(|err| {
        eprintln!("\nerror: {err}\n");
        print_help();
        process::exit(1);
    });

    if !config.quiet {
        print_banner();
        print_plan(&config);
    }

    let stop = Arc::new(AtomicBool::new(false));
    let attempts = Arc::new(AtomicU64::new(0));
    let (tx, rx) = mpsc::channel::<ResultHit>();
    let start = Instant::now();

    for id in 0..config.threads {
        let stop = stop.clone();
        let attempts = attempts.clone();
        let tx = tx.clone();
        let prefix = config.prefix.clone();
        let suffix = config.suffix.clone();

        thread::spawn(move || {
            let mut seed_rng = [0u8; 32];
            seed_rng[..8].copy_from_slice(&(id as u64).to_le_bytes());
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0);
            seed_rng[8..16].copy_from_slice(&nanos.to_le_bytes());
            let mut rng = StdRng::from_seed(seed_rng);
            let mut local = 0u64;

            loop {
                if local & 1023 == 0 && stop.load(Ordering::Relaxed) {
                    break;
                }

                let mut seed = [0u8; 32];
                rng.fill_bytes(&mut seed);

                let signing = SigningKey::from_bytes(&seed);
                let pubkey = signing.verifying_key().to_bytes();
                let address = bs58::encode(pubkey).into_string();

                local += 1;
                if local >= 16_384 {
                    attempts.fetch_add(local, Ordering::Relaxed);
                    local = 0;
                }

                if (prefix.is_empty() || address.starts_with(&prefix))
                    && (suffix.is_empty() || address.ends_with(&suffix))
                {
                    let total = attempts.fetch_add(local, Ordering::Relaxed) + local;
                    let keypair = encode_solana_keypair(&seed, &pubkey);
                    let _ = tx.send(ResultHit {
                        address,
                        seed,
                        keypair,
                        attempts: total,
                    });
                    stop.store(true, Ordering::Relaxed);
                    break;
                }
            }

            if local > 0 {
                attempts.fetch_add(local, Ordering::Relaxed);
            }
        });
    }
    drop(tx);

    let mut last_progress = Instant::now();
    loop {
        if let Some(d) = config.duration {
            if start.elapsed() >= d {
                stop.store(true, Ordering::Relaxed);
                thread::sleep(Duration::from_millis(150));
                let n = attempts.load(Ordering::Relaxed);
                let secs = start.elapsed().as_secs_f64();
                println!(
                    "BENCH attempts={} seconds={:.3} keys_per_sec={:.0} threads={}",
                    n,
                    secs,
                    n as f64 / secs,
                    config.threads
                );
                return;
            }
        }

        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(hit) => {
                stop.store(true, Ordering::Relaxed);
                print_hit(&hit, start.elapsed(), config.threads);
                return;
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                if !config.quiet
                    && config.duration.is_none()
                    && last_progress.elapsed() >= Duration::from_secs(3)
                {
                    print_progress(attempts.load(Ordering::Relaxed), start.elapsed(), &config);
                    last_progress = Instant::now();
                }
            }
            Err(_) => return,
        }
    }
}

fn parse_args() -> Result<Config, String> {
    let args: Vec<String> = env::args().collect();
    if args.iter().any(|a| a == "--help" || a == "-h") {
        print_help();
        process::exit(0);
    }

    let prefix = arg_value(&args, "--prefix").unwrap_or_default();
    let suffix = arg_value(&args, "--suffix").unwrap_or_default();
    let threads = arg_value(&args, "--threads")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or_else(|| {
            thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(8)
        });
    let duration = arg_value(&args, "--duration").and_then(|s| parse_duration(&s));
    let quiet = args.iter().any(|a| a == "--quiet" || a == "-q");

    if prefix.is_empty() && suffix.is_empty() {
        return Err("at least one of --prefix or --suffix is required".into());
    }
    if threads == 0 {
        return Err("--threads must be >= 1".into());
    }
    if !is_base58(&prefix) {
        return Err(format!("invalid base58 prefix: {prefix:?}"));
    }
    if !is_base58(&suffix) {
        return Err(format!("invalid base58 suffix: {suffix:?}"));
    }

    Ok(Config {
        prefix,
        suffix,
        threads,
        duration,
        quiet,
    })
}

fn arg_value(args: &[String], name: &str) -> Option<String> {
    args.windows(2).find(|w| w[0] == name).map(|w| w[1].clone())
}

fn print_banner() {
    println!(
        r#"
   ___                  ___       __    __
  / _ | ___  ___  ___ _/ _ | ___ / /___/ /______ ___ ___
 / __ |/ _ \/ _ \/ _ `/ __ |/ -_) / __/  '_/ -_) -_) _ \
/_/ |_\ .__/ .__/\_,_/_/ |_|\__/_/\__/_/\_\\__/\__/_//_/
     /_/  /_/        Solana Vanity Grinder
"#
    );
}

fn print_help() {
    println!(
        r#"Solana vanity address grinder

Usage:
  solvanity-rs --prefix puter [--threads 16]
  solvanity-rs --suffix sol
  solvanity-rs --prefix pu --suffix ter

Options:
  --prefix <text>    Match address prefix
  --suffix <text>    Match address suffix
  --threads <n>      Worker threads. On this Mac, 8-16 is usually best.
  --duration <time>  Benchmark mode, e.g. 10s, 1m. Does not wait for a match.
  --quiet, -q        Less output
  --help, -h         Show help

Base58 excludes: 0, I, O, l
Security: keys are printed to stdout only. Run offline for real wallets.
"#
    );
}

fn print_plan(config: &Config) {
    let pattern_len = config.prefix.len() + config.suffix.len();
    let search_space = 58_f64.powi(pattern_len as i32);
    let p50 = (0.5_f64.ln() / (-1.0 / search_space).ln_1p()).abs();
    let p95 = (0.05_f64.ln() / (-1.0 / search_space).ln_1p()).abs();

    let mode = match (config.prefix.is_empty(), config.suffix.is_empty()) {
        (false, false) => format!("prefix {:?} + suffix {:?}", config.prefix, config.suffix),
        (false, true) => format!("prefix {:?}", config.prefix),
        (true, false) => format!("suffix {:?}", config.suffix),
        _ => unreachable!(),
    };

    println!("Target       : {mode}");
    println!("Threads      : {}", config.threads);
    println!("Search space : {:.0}", search_space);
    println!(
        "Probability  : p50 {:.0} attempts | p95 {:.0} attempts",
        p50, p95
    );
    if config.duration.is_some() {
        println!("Mode         : benchmark");
    }
    println!("Controls     : Ctrl+C to stop");
    println!();
}

fn print_progress(attempts: u64, elapsed: Duration, config: &Config) {
    let secs = elapsed.as_secs_f64().max(0.001);
    let rate = attempts as f64 / secs;
    let pattern_len = config.prefix.len() + config.suffix.len();
    let search_space = 58_f64.powi(pattern_len as i32);
    let p50 = (0.5_f64.ln() / (-1.0 / search_space).ln_1p()).abs();
    let remaining = (p50 - attempts as f64).max(0.0);
    let eta = if rate > 0.0 {
        format_duration(Duration::from_secs_f64(remaining / rate))
    } else {
        "?".to_string()
    };

    println!(
        "  ... {:>12} attempts | {:>9.0} keys/sec | p50 ETA ~{}",
        attempts, rate, eta
    );
}

fn print_hit(hit: &ResultHit, elapsed: Duration, threads: usize) {
    let secs = elapsed.as_secs_f64().max(0.001);
    let rate = hit.attempts as f64 / secs;
    println!("{}", "=".repeat(64));
    println!("MATCH FOUND!");
    println!("{}", "=".repeat(64));
    println!("Address      : {}", hit.address);
    println!("Private Seed : {}", hex_seed(&hit.seed));
    println!("Keypair bs58 : {}", hit.keypair);
    println!("Attempts     : {}", hit.attempts);
    println!("Time         : {}", format_duration(elapsed));
    println!("Speed        : {:.0} keys/sec ({} threads)", rate, threads);
    println!("{}", "=".repeat(64));
    println!(
        "\nImport note: Solana wallets usually expect the 64-byte keypair, shown above as base58."
    );
}

fn encode_solana_keypair(seed: &[u8; 32], pubkey: &[u8; 32]) -> String {
    let mut keypair = [0u8; 64];
    keypair[..32].copy_from_slice(seed);
    keypair[32..].copy_from_slice(pubkey);
    bs58::encode(keypair).into_string()
}

fn is_base58(s: &str) -> bool {
    s.bytes().all(|b| BASE58.as_bytes().contains(&b))
}

fn parse_duration(s: &str) -> Option<Duration> {
    if let Some(n) = s.strip_suffix("ms") {
        n.parse::<f64>()
            .ok()
            .map(|v| Duration::from_secs_f64(v / 1000.0))
    } else if let Some(n) = s.strip_suffix('s') {
        n.parse::<f64>().ok().map(Duration::from_secs_f64)
    } else if let Some(n) = s.strip_suffix('m') {
        n.parse::<f64>()
            .ok()
            .map(|v| Duration::from_secs_f64(v * 60.0))
    } else {
        None
    }
}

fn format_duration(d: Duration) -> String {
    let secs = d.as_secs();
    if secs < 60 {
        format!("{}s", secs)
    } else if secs < 3600 {
        format!("{}m {}s", secs / 60, secs % 60)
    } else {
        format!("{:.1}h", d.as_secs_f64() / 3600.0)
    }
}

fn hex_seed(seed: &[u8; 32]) -> String {
    seed.iter().map(|b| format!("{:02x}", b)).collect()
}
