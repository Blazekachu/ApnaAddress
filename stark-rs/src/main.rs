use bip32::{DerivationPath, XPrv};
use bip39::Mnemonic;
use rand::{rngs::StdRng, RngCore, SeedableRng};
use sha2::{Digest, Sha256};
use starknet_core::utils::get_contract_address;
use starknet_crypto::Felt;
use std::env;
use std::process;
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    mpsc, Arc,
};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

// ── Class Hashes ──────────────────────────────────────────────────────

// Ready (ArgentX) — v0.4.0 class hash (verified: seed restore produces matching address)
const ARGENT_CLASS_HASH: &str =
    "0x036078334509b514626504edc9fb252328d1a240e4e948bef8d0c08dff45927f";

// Braavos v1.2.0 base account (verified: seed restore produces matching address)
const BRAAVOS_CLASS_HASH: &str =
    "0x03d16c7a9a60b0593bd202f660a28c5d76e0403601d9ccc7e4fa253b6a70c201";

// Xverse — recompiled ArgentX v0.4.0 for cheaper gas (from xverse-core/starknet/constants.ts)
const XVERSE_CLASS_HASH: &str =
    "0x0663fc01a0dbe1bacc4cd2a4c856eb9784b255a20988aa33d4d52b6fc20bd024";

// Stark curve order
const STARK_CURVE_ORDER: &str =
    "0800000000000010ffffffffffffffffb781126dcae7b2321e66a241adc64d2f";

// ── Types ─────────────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq)]
enum Wallet {
    Argent,
    Braavos,
    Xverse,
}

impl Wallet {
    fn name(&self) -> &'static str {
        match self {
            Wallet::Argent => "Ready (ArgentX)",
            Wallet::Braavos => "Braavos",
            Wallet::Xverse => "Xverse",
        }
    }

    fn class_hash(&self) -> Felt {
        match self {
            Wallet::Argent => Felt::from_hex(ARGENT_CLASS_HASH).unwrap(),
            Wallet::Braavos => Felt::from_hex(BRAAVOS_CLASS_HASH).unwrap(),
            Wallet::Xverse => Felt::from_hex(XVERSE_CLASS_HASH).unwrap(),
        }
    }

    fn constructor_calldata(&self, public_key: Felt) -> Vec<Felt> {
        match self {
            // Ready + Xverse: ArgentX v0.4.0 format [owner_variant=0, public_key, guardian=None(1)]
            Wallet::Argent | Wallet::Xverse => vec![Felt::ZERO, public_key, Felt::ONE],
            // Braavos: [public_key]
            Wallet::Braavos => vec![public_key],
        }
    }
}

#[derive(Clone, Copy, PartialEq)]
enum OutputMode {
    Key,
    Seed,
}

#[derive(Clone)]
struct Config {
    wallet: Wallet,
    prefix: String,
    suffix: String,
    threads: usize,
    duration: Option<Duration>,
    quiet: bool,
    passphrase: Option<String>,
    output: OutputMode,
}

struct Hit {
    address: String,
    private_key: String,
    public_key: String,
    mnemonic: Option<String>,
    attempts: u64,
}

// ── Address Computation ───────────────────────────────────────────────

fn compute_address(wallet: Wallet, public_key: Felt) -> Felt {
    let class_hash = wallet.class_hash();
    let calldata = wallet.constructor_calldata(public_key);
    let salt = public_key;
    let deployer = Felt::ZERO;
    get_contract_address(salt, class_hash, &calldata, deployer)
}

fn felt_to_hex(felt: Felt) -> String {
    // Full 64-char zero-padded for matching
    let bytes = felt.to_bytes_be();
    let hex: String = bytes.iter().map(|b| format!("{:02x}", b)).collect();
    format!("0x{}", hex)
}

fn felt_to_hex_display(felt: Felt) -> String {
    // Full 66-char format matching Ready/ArgentX display: 0x + 64 hex chars
    let bytes = felt.to_bytes_be();
    let hex: String = bytes.iter().map(|b| format!("{:02x}", b)).collect();
    format!("0x{}", hex)
}

// ── Seed Mode: Mnemonic → ETH key → Stark key (Ready's actual flow) ──
//
// Ready (ArgentX) derives Stark keys from mnemonics like this:
// 1. BIP39 mnemonic → BIP39 seed (standard PBKDF2-HMAC-SHA512)
// 2. BIP32 derive m/44'/60'/0'/0/0 → Ethereum private key
// 3. Use ETH private key as seed for a NEW HD tree
// 4. BIP32 derive m/2645'/1195502025'/1148870696'/0'/0'/0 from that tree
// 5. grindKey(child.privateKey) → Stark private key

fn mnemonic_to_stark_privkey(mnemonic: &Mnemonic, wallet: Wallet) -> Felt {
    let bip39_seed = mnemonic.to_seed("");
    let stark_path: DerivationPath = "m/44'/9004'/0'/0/0".parse().unwrap();

    let hd_seed: Vec<u8> = match wallet {
        Wallet::Argent => {
            // Ready (ArgentX): mnemonic → ETH key at m/44'/60'/0'/0/0 → use as HD seed
            let eth_path: DerivationPath = "m/44'/60'/0'/0/0".parse().unwrap();
            let eth_xprv = XPrv::derive_from_path(&bip39_seed, &eth_path).unwrap();
            eth_xprv.private_key().to_bytes().to_vec()
        }
        Wallet::Braavos | Wallet::Xverse => {
            // Braavos + Xverse: mnemonic → BIP39 seed directly as HD seed
            bip39_seed.to_vec()
        }
    };

    let stark_child = XPrv::derive_from_path(&hd_seed, &stark_path).unwrap();
    let derived_key = stark_child.private_key().to_bytes();
    grind_key(&derived_key)
}

// ── grindKey (matching ethers.js / starkware-crypto implementation) ───

fn grind_key(key_seed: &[u8]) -> Felt {
    let order = hex_to_bytes32(STARK_CURVE_ORDER);
    // limit = 2^256 - (2^256 % order)
    // sha256EcMaxDigest = 2^256
    // maxAllowedVal = sha256EcMaxDigest - (sha256EcMaxDigest % order)
    let limit = compute_grind_limit(&order);

    for i in 0u32.. {
        let key = hash_key_with_index(key_seed, i);
        if bytes_lt(&key, &limit) {
            let result = bytes_mod(&key, &order);
            if result.iter().any(|&b| b != 0) {
                return Felt::from_bytes_be(&result);
            }
        }
    }
    unreachable!()
}

fn hash_key_with_index(key: &[u8], index: u32) -> [u8; 32] {
    // Match ethers.js: utils.concat([utils.arrayify(key), utils.arrayify(index)])
    // utils.arrayify on a small number produces minimal bytes
    let mut hasher = Sha256::new();
    hasher.update(key);
    // arrayify(0) = [0], arrayify(1) = [1], arrayify(256) = [1, 0], etc.
    if index == 0 {
        hasher.update(&[0u8]);
    } else {
        let be_bytes = index.to_be_bytes();
        let start = be_bytes.iter().position(|&b| b != 0).unwrap_or(3);
        hasher.update(&be_bytes[start..]);
    }
    hasher.finalize().into()
}

fn compute_grind_limit(order: &[u8; 32]) -> [u8; 32] {
    // limit = 2^256 - (2^256 % order)
    // Since 2^256 doesn't fit in 32 bytes, compute: -((-order) % order) isn't right either
    // Actually: 2^256 mod order = (2^256 - order*floor(2^256/order))
    // Simpler: remainder = negate(order) when order doesn't divide 2^256
    // 2^256 mod N: since 2^256 = N*q + r, and we can compute r = (-N) mod 2^256 when N < 2^256
    // neg_order = 2^256 - order (two's complement)
    let mut neg_order = [0u8; 32];
    let mut borrow: u16 = 0;
    for i in (0..32).rev() {
        let val = 256u16 - order[i] as u16 - borrow;
        if i == 31 {
            // subtract from 0, first iteration
        }
        neg_order[i] = val as u8;
        borrow = if val > 255 { 0 } else { 1 };
    }
    // Actually this is wrong for the first byte. Let me just use a simpler approach.
    // remainder = 0 - order in 256-bit arithmetic = two's complement
    let mut rem = [0u8; 32];
    let mut carry: u16 = 1;
    for i in (0..32).rev() {
        let val = (!order[i]) as u16 + carry;
        rem[i] = val as u8;
        carry = val >> 8;
    }
    // rem = 2^256 - order = 2^256 mod order (since order < 2^256)
    // But we need: 2^256 mod order, which could be larger than order
    // So reduce: rem = rem % order
    let remainder = bytes_mod(&rem, order);
    // limit = 2^256 - remainder
    // But we can't represent 2^256. Instead, limit = -remainder in 256-bit
    if remainder.iter().all(|&b| b == 0) {
        return [0xff; 32]; // no limit needed
    }
    let mut limit = [0u8; 32];
    let mut carry2: u16 = 1;
    for i in (0..32).rev() {
        let val = (!remainder[i]) as u16 + carry2;
        limit[i] = val as u8;
        carry2 = val >> 8;
    }
    limit
}

fn hex_to_bytes32(hex: &str) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    let clean = hex.strip_prefix("0x").unwrap_or(hex);
    let padded = format!("{:0>64}", clean);
    for i in 0..32 {
        bytes[i] = u8::from_str_radix(&padded[i * 2..i * 2 + 2], 16).unwrap();
    }
    bytes
}

fn bytes_lt(a: &[u8; 32], b: &[u8; 32]) -> bool {
    for i in 0..32 {
        if a[i] < b[i] {
            return true;
        }
        if a[i] > b[i] {
            return false;
        }
    }
    false // equal
}

fn bytes_mod(value: &[u8; 32], modulus: &[u8; 32]) -> [u8; 32] {
    let mut result = *value;
    while bytes_ge(&result, modulus) {
        bytes_sub(&mut result, modulus);
    }
    result
}

fn bytes_ge(a: &[u8; 32], b: &[u8; 32]) -> bool {
    for i in 0..32 {
        if a[i] > b[i] {
            return true;
        }
        if a[i] < b[i] {
            return false;
        }
    }
    true
}

fn bytes_sub(a: &mut [u8; 32], b: &[u8; 32]) {
    let mut borrow: i16 = 0;
    for i in (0..32).rev() {
        let diff = a[i] as i16 - b[i] as i16 - borrow;
        if diff < 0 {
            a[i] = (diff + 256) as u8;
            borrow = 1;
        } else {
            a[i] = diff as u8;
            borrow = 0;
        }
    }
}

// ── BIP39 seed from mnemonic ──────────────────────────────────────────

fn mnemonic_to_seed(mnemonic: &Mnemonic) -> [u8; 64] {
    mnemonic.to_seed("")
}

// ── Workers ───────────────────────────────────────────────────────────

fn worker_key_mode(
    id: usize,
    config: &Config,
    stop: &AtomicBool,
    attempts: &AtomicU64,
    tx: &mpsc::Sender<Hit>,
) {
    let mut local_attempts = 0u64;

    let mut seed = [0u8; 32];
    if let Some(ref pp) = config.passphrase {
        let hash = Sha256::digest(pp.as_bytes());
        seed.copy_from_slice(&hash);
        let offset = (id as u64).to_le_bytes();
        for i in 0..8 {
            seed[24 + i] ^= offset[i];
        }
    } else {
        seed[..8].copy_from_slice(&(id as u64).to_le_bytes());
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        seed[8..16].copy_from_slice(&nanos.to_le_bytes());
        let pid = process::id() as u64;
        seed[16..24].copy_from_slice(&pid.to_le_bytes());
    }
    let mut rng = StdRng::from_seed(seed);

    let prefix = config.prefix.to_lowercase();
    let suffix = config.suffix.to_lowercase();

    loop {
        if local_attempts & 1023 == 0 && stop.load(Ordering::Relaxed) {
            break;
        }

        let mut key_bytes = [0u8; 32];
        rng.fill_bytes(&mut key_bytes);
        key_bytes[0] &= 0x07;

        let private_key = Felt::from_bytes_be(&key_bytes);
        if private_key == Felt::ZERO {
            continue;
        }

        let public_key = starknet_crypto::get_public_key(&private_key);
        let address = compute_address(config.wallet, public_key);
        let addr_hex = felt_to_hex(address);

        let addr_body = addr_hex[2..].trim_start_matches('0');
        let prefix_ok = prefix.is_empty() || addr_body.starts_with(&prefix);
        let suffix_ok = suffix.is_empty() || addr_hex.ends_with(&suffix);

        local_attempts += 1;
        if local_attempts >= 8192 {
            attempts.fetch_add(local_attempts, Ordering::Relaxed);
            local_attempts = 0;
        }

        if prefix_ok && suffix_ok {
            let total = attempts.fetch_add(local_attempts, Ordering::Relaxed) + local_attempts;
            let _ = tx.send(Hit {
                address: felt_to_hex_display(address),
                private_key: felt_to_hex_display(private_key),
                public_key: felt_to_hex_display(public_key),
                mnemonic: None,
                attempts: total,
            });
            stop.store(true, Ordering::Relaxed);
            break;
        }
    }

    if local_attempts > 0 {
        attempts.fetch_add(local_attempts, Ordering::Relaxed);
    }
}

fn worker_seed_mode(
    id: usize,
    config: &Config,
    stop: &AtomicBool,
    attempts: &AtomicU64,
    tx: &mpsc::Sender<Hit>,
) {
    let mut local_attempts = 0u64;

    let mut rng_seed = [0u8; 32];
    rng_seed[..8].copy_from_slice(&(id as u64).to_le_bytes());
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    rng_seed[8..16].copy_from_slice(&nanos.to_le_bytes());
    let pid = process::id() as u64;
    rng_seed[16..24].copy_from_slice(&pid.to_le_bytes());
    let mut rng = StdRng::from_seed(rng_seed);

    let prefix = config.prefix.to_lowercase();
    let suffix = config.suffix.to_lowercase();

    loop {
        if local_attempts & 255 == 0 && stop.load(Ordering::Relaxed) {
            break;
        }

        // Generate random 16 bytes of entropy (12 words = 128 bits)
        let mut entropy = [0u8; 16];
        rng.fill_bytes(&mut entropy);

        let mnemonic = Mnemonic::from_entropy(&entropy).unwrap();

        // Use Ready's actual derivation: mnemonic → ETH key → Stark key
        let private_key = mnemonic_to_stark_privkey(&mnemonic, config.wallet);
        if private_key == Felt::ZERO {
            continue;
        }

        let public_key = starknet_crypto::get_public_key(&private_key);
        let address = compute_address(config.wallet, public_key);
        let addr_hex = felt_to_hex(address);

        let addr_body = addr_hex[2..].trim_start_matches('0');
        let prefix_ok = prefix.is_empty() || addr_body.starts_with(&prefix);
        let suffix_ok = suffix.is_empty() || addr_hex.ends_with(&suffix);

        local_attempts += 1;
        if local_attempts >= 1024 {
            attempts.fetch_add(local_attempts, Ordering::Relaxed);
            local_attempts = 0;
        }

        if prefix_ok && suffix_ok {
            let total = attempts.fetch_add(local_attempts, Ordering::Relaxed) + local_attempts;
            let _ = tx.send(Hit {
                address: felt_to_hex_display(address),
                private_key: felt_to_hex_display(private_key),
                public_key: felt_to_hex_display(public_key),
                mnemonic: Some(mnemonic.to_string()),
                attempts: total,
            });
            stop.store(true, Ordering::Relaxed);
            break;
        }
    }

    if local_attempts > 0 {
        attempts.fetch_add(local_attempts, Ordering::Relaxed);
    }
}

// ── CLI ────────────────────────────────────────────────────────────────

fn parse_args() -> Result<Config, String> {
    let args: Vec<String> = env::args().collect();
    if args.iter().any(|a| a == "--help" || a == "-h") {
        print_help();
        process::exit(0);
    }

    let mut wallet: Option<Wallet> = None;
    let mut prefix = String::new();
    let mut suffix = String::new();
    let mut threads = None;
    let mut duration = None;
    let mut quiet = false;
    let mut passphrase = None;
    let mut output = OutputMode::Key;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--wallet" | "-w" => {
                i += 1;
                let w = args.get(i).ok_or("--wallet needs a value")?;
                wallet = Some(match w.to_lowercase().as_str() {
                    "argent" | "argentx" | "ready" => Wallet::Argent,
                    "braavos" => Wallet::Braavos,
                    "xverse" => Wallet::Xverse,
                    _ => {
                        return Err(format!(
                            "unknown wallet: {:?}. Use 'argent', 'braavos', or 'xverse'",
                            w
                        ))
                    }
                });
            }
            "--prefix" => {
                i += 1;
                prefix = args
                    .get(i)
                    .cloned()
                    .ok_or("--prefix needs a value")?
                    .to_lowercase();
            }
            "--suffix" => {
                i += 1;
                suffix = args
                    .get(i)
                    .cloned()
                    .ok_or("--suffix needs a value")?
                    .to_lowercase();
            }
            "--threads" => {
                i += 1;
                let t: usize = args
                    .get(i)
                    .ok_or("--threads needs a value".to_string())
                    .and_then(|s| {
                        s.parse().map_err(|e: std::num::ParseIntError| e.to_string())
                    })?;
                threads = Some(t);
            }
            "--duration" => {
                i += 1;
                let d = args.get(i).ok_or("--duration needs a value")?;
                duration = Some(parse_duration(d).ok_or("invalid duration (use 5s, 1m)")?);
            }
            "--passphrase" => {
                i += 1;
                passphrase = Some(
                    args.get(i)
                        .cloned()
                        .ok_or("--passphrase needs a value")?,
                );
            }
            "--output" | "-o" => {
                i += 1;
                let o = args.get(i).ok_or("--output needs a value")?;
                output = match o.to_lowercase().as_str() {
                    "key" => OutputMode::Key,
                    "seed" => OutputMode::Seed,
                    _ => return Err(format!("unknown output mode: {:?}. Use 'key' or 'seed'", o)),
                };
            }
            "--quiet" | "-q" => quiet = true,
            other => {
                return Err(format!("unknown option: {other}"));
            }
        }
        i += 1;
    }

    let wallet = wallet.ok_or("--wallet is required (argent, braavos, or xverse)")?;

    if prefix.is_empty() && suffix.is_empty() {
        return Err("at least one of --prefix or --suffix is required".into());
    }

    if !prefix.is_empty() && !is_hex(&prefix) {
        return Err(format!(
            "invalid hex prefix: {:?}. Allowed: 0-9, a-f",
            prefix
        ));
    }
    if !suffix.is_empty() && !is_hex(&suffix) {
        return Err(format!(
            "invalid hex suffix: {:?}. Allowed: 0-9, a-f",
            suffix
        ));
    }

    if output == OutputMode::Seed && passphrase.is_some() {
        return Err("--passphrase cannot be used with --output seed".into());
    }

    let threads = threads.unwrap_or_else(|| {
        thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(8)
    });

    if threads == 0 {
        return Err("--threads must be >= 1".into());
    }

    Ok(Config {
        wallet,
        prefix,
        suffix,
        threads,
        duration,
        quiet,
        passphrase,
        output,
    })
}

fn is_hex(s: &str) -> bool {
    s.bytes().all(|b| b.is_ascii_hexdigit())
}

fn print_help() {
    println!(
        r#"Starknet Vanity Address Generator

Usage:
  starkvanity --wallet argent --prefix dead
  starkvanity --wallet braavos --suffix cafe
  starkvanity --wallet argent --prefix 069 --suffix 420
  starkvanity --wallet argent --prefix dead --output seed

Options:
  --wallet, -w <type>  Wallet type: argent, braavos, or xverse (required)
  --prefix <hex>       Match start of address (after 0x)
  --suffix <hex>       Match end of address
  --output, -o <mode>  Output mode: key (default) or seed (12-word mnemonic)
  --threads <n>        Worker threads (default: CPU cores)
  --passphrase "x"     Derive starting key from SHA256 (key mode only)
  --duration <time>    Benchmark mode, e.g. 10s, 1m
  --quiet, -q          Less output
  --help, -h           Show help

Output modes:
  key   Raw private key (faster). Import via private key in wallet settings.
  seed  12-word BIP39 mnemonic (slower). Import via seed phrase in wallet.

Charset: hex (0-9, a-f). Case-insensitive input.

Security: Keys are printed to stdout only. Nothing is written to disk.
          Run offline. Clear your terminal after copying.
"#
    );
}

fn print_banner() {
    println!(
        r#"
  _____ _             _   __     __          _ _
 / ____| |           | |  \ \   / /         (_) |
| (___ | |_ __ _ _ __| | _\ \_/ /_ _ _ __   _| |_ _   _
 \___ \| __/ _` | '__| |/ /\   / _` | '_ \ | | __| | | |
 ____) | || (_| | |  |   <  | | (_| | | | || | |_| |_| |
|_____/ \__\__,_|_|  |_|\_\ |_|\__,_|_| |_||_|\__|\__, |
                                                     __/ |
         Starknet Vanity Address Grinder            |___/
"#
    );
}

fn print_plan(config: &Config) {
    let pattern_len = config.prefix.len() + config.suffix.len();
    let search_space = 16_u64.pow(pattern_len as u32);

    let mode = match (config.prefix.is_empty(), config.suffix.is_empty()) {
        (false, false) => format!("prefix {:?} + suffix {:?}", config.prefix, config.suffix),
        (false, true) => format!("prefix {:?}", config.prefix),
        (true, false) => format!("suffix {:?}", config.suffix),
        _ => unreachable!(),
    };

    let output_label = match config.output {
        OutputMode::Key => "private key",
        OutputMode::Seed => "12-word seed phrase",
    };

    println!("Wallet       : {}", config.wallet.name());
    println!("Target       : {mode}");
    println!("Output       : {output_label}");
    println!("Threads      : {}", config.threads);
    println!("Search space : {}", search_space);
    println!("Avg attempts : {}", search_space / 2);

    if config.passphrase.is_some() {
        println!("Passphrase   : enabled (deterministic start key)");
    }
    if config.output == OutputMode::Seed {
        println!("Note         : seed mode is slower (BIP39+BIP32+grindKey per attempt)");
    }
    if config.duration.is_some() {
        println!("Mode         : benchmark");
    }
    println!("Controls     : Ctrl+C to stop");
    println!();
}

// ── Main ───────────────────────────────────────────────────────────────

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
    let (tx, rx) = mpsc::channel::<Hit>();
    let start = Instant::now();

    for id in 0..config.threads {
        let stop = stop.clone();
        let attempts = attempts.clone();
        let tx = tx.clone();
        let config = config.clone();

        thread::spawn(move || match config.output {
            OutputMode::Key => worker_key_mode(id, &config, &stop, &attempts, &tx),
            OutputMode::Seed => worker_seed_mode(id, &config, &stop, &attempts, &tx),
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
                print_hit(&hit, start.elapsed(), &config);
                return;
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                if !config.quiet
                    && config.duration.is_none()
                    && last_progress.elapsed() >= Duration::from_secs(3)
                {
                    print_progress(
                        attempts.load(Ordering::Relaxed),
                        start.elapsed(),
                        &config,
                    );
                    last_progress = Instant::now();
                }
            }
            Err(_) => return,
        }
    }
}

fn print_progress(attempts: u64, elapsed: Duration, config: &Config) {
    let secs = elapsed.as_secs_f64().max(0.001);
    let rate = attempts as f64 / secs;
    let pattern_len = config.prefix.len() + config.suffix.len();
    let search_space = 16_f64.powi(pattern_len as i32);
    let avg = search_space / 2.0;
    let remaining = (avg - attempts as f64).max(0.0);
    let eta = if rate > 0.0 {
        format_duration(Duration::from_secs_f64(remaining / rate))
    } else {
        "?".to_string()
    };

    println!(
        "  ... {:>12} attempts | {:>9.0} keys/sec | avg ETA ~{}",
        attempts, rate, eta
    );
}

fn print_hit(hit: &Hit, elapsed: Duration, config: &Config) {
    let secs = elapsed.as_secs_f64().max(0.001);
    let rate = hit.attempts as f64 / secs;

    println!("{}", "=".repeat(64));
    println!("MATCH FOUND!");
    println!("{}", "=".repeat(64));
    println!("Wallet       : {}", config.wallet.name());
    println!("Address      : {}", hit.address);
    if let Some(ref mnemonic) = hit.mnemonic {
        println!("Seed Phrase  : {}", mnemonic);
    }
    println!("Private Key  : {}", hit.private_key);
    println!("Public Key   : {}", hit.public_key);
    println!(
        "Class Hash   : {}",
        felt_to_hex_display(config.wallet.class_hash())
    );
    println!("Attempts     : {}", hit.attempts);
    println!("Time         : {}", format_duration(elapsed));
    println!(
        "Speed        : {:.0} keys/sec ({} threads)",
        rate, config.threads
    );
    println!("{}", "=".repeat(64));
    println!();

    if hit.mnemonic.is_some() {
        println!(
            "Import: Use \"Restore wallet\" in {} with the 12-word seed phrase.",
            config.wallet.name()
        );
        println!("        Write down the seed phrase on paper. Do NOT store digitally.");
    } else {
        println!(
            "Import: Use \"Import existing wallet\" in {} with the private key.",
            config.wallet.name()
        );
    }
    println!();
}

// ── Helpers ────────────────────────────────────────────────────────────

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
