use rand::{rngs::StdRng, RngCore, SeedableRng};
use ripemd::Ripemd160;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use sha2::{Digest, Sha256};
use std::env;
use std::process;
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    mpsc, Arc,
};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

// ── Constants ──────────────────────────────────────────────────────────
const BASE58: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const BECH32_CHARSET: &[u8] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const BECH32_GEN: [u32; 5] = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];

// secp256k1 curve order n (big-endian, 32 bytes)
const CURVE_ORDER: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36,
    0x41, 0x41,
];

#[derive(Clone, Copy, PartialEq, Debug)]
enum AddrType {
    Legacy,    // P2PKH  (starts with 1)
    Nested,    // P2SH   (starts with 3)
    NativeSeg, // P2WPKH (starts with bc1q)
    Taproot,   // P2TR   (starts with bc1p)
}

impl AddrType {
    fn version_prefix(&self) -> &'static str {
        match self {
            AddrType::Legacy => "1",
            AddrType::Nested => "3",
            AddrType::NativeSeg => "bc1q",
            AddrType::Taproot => "bc1p",
        }
    }
    fn is_bech32(&self) -> bool {
        matches!(self, AddrType::NativeSeg | AddrType::Taproot)
    }
    fn charset_size(&self) -> usize {
        if self.is_bech32() { 32 } else { 58 }
    }
}

fn parse_addr_type(s: &str) -> Option<AddrType> {
    match s.to_lowercase().as_str() {
        "legacy" | "p2pkh" => Some(AddrType::Legacy),
        "nested" | "nested-segwit" | "p2sh" => Some(AddrType::Nested),
        "native" | "native-segwit" | "segwit" | "p2wpkh" => Some(AddrType::NativeSeg),
        "taproot" | "p2tr" => Some(AddrType::Taproot),
        _ => None,
    }
}

#[derive(Clone)]
struct Config {
    addr_type: AddrType,
    prefix: String,
    suffix: String,
    threads: usize,
    duration: Option<Duration>,
    quiet: bool,
    passphrase: Option<String>,
}

struct Hit {
    address: String,
    wif: String,
    privkey_hex: String,
    pubkey_hex: String,
    all_addresses: AllAddresses,
    attempts: u64,
}

struct AllAddresses {
    legacy: String,
    nested: String,
    native_segwit: String,
    taproot: String,
}

// ── Crypto helpers ─────────────────────────────────────────────────────

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

fn hash160(data: &[u8]) -> [u8; 20] {
    let mut hasher = Ripemd160::new();
    hasher.update(sha256(data));
    hasher.finalize().into()
}

// ── Base58 encoding ────────────────────────────────────────────────────

fn base58_encode(bytes: &[u8]) -> String {
    let leading_zeros = bytes.iter().take_while(|&&b| b == 0).count();
    let mut digits = Vec::<u8>::new();
    for &byte in bytes {
        let mut carry = byte as u32;
        for d in digits.iter_mut() {
            let v = (*d as u32) * 256 + carry;
            *d = (v % 58) as u8;
            carry = v / 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }
    let mut result = vec![b'1'; leading_zeros];
    for &d in digits.iter().rev() {
        result.push(BASE58[d as usize]);
    }
    String::from_utf8(result).unwrap()
}

fn base58check_encode(version: u8, payload: &[u8]) -> String {
    let mut full = vec![version];
    full.extend_from_slice(payload);
    let checksum = &sha256(&sha256(&full))[..4];
    full.extend_from_slice(checksum);
    base58_encode(&full)
}

// ── Bech32/Bech32m encoding ────────────────────────────────────────────

fn bech32_polymod(values: &[u8]) -> u32 {
    let mut chk: u32 = 1;
    for &v in values {
        let b = (chk >> 25) as u8;
        chk = ((chk & 0x1ffffff) << 5) ^ v as u32;
        for j in 0..5 {
            if (b >> j) & 1 != 0 {
                chk ^= BECH32_GEN[j as usize];
            }
        }
    }
    chk
}

fn bech32_encode(witness_version: u8, program: &[u8], bech32m: bool) -> String {
    let mut data5: Vec<u8> = vec![witness_version];
    let mut acc = 0u32;
    let mut bits = 0u32;
    for &byte in program {
        acc = (acc << 8) | byte as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            data5.push(((acc >> bits) & 31) as u8);
        }
    }
    if bits > 0 {
        data5.push(((acc << (5 - bits)) & 31) as u8);
    }

    let hrp_exp: Vec<u8> = vec![0, 0, 3, 3, 0, 2, 3];
    let enc: u32 = if bech32m { 0x2bc830a3 } else { 1 };
    let mut values = hrp_exp;
    values.extend_from_slice(&data5);
    values.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
    let polymod = bech32_polymod(&values) ^ enc;

    let mut checksum = Vec::new();
    for i in 0..6 {
        checksum.push(((polymod >> (5 * (5 - i))) & 31) as u8);
    }

    let mut combined = data5;
    combined.extend_from_slice(&checksum);

    let mut result = String::from("bc1");
    for &v in &combined {
        result.push(BECH32_CHARSET[v as usize] as char);
    }
    result
}

// ── Address generation ─────────────────────────────────────────────────

fn legacy_address(pubkey: &[u8]) -> String {
    let h = hash160(pubkey);
    base58check_encode(0x00, &h)
}

fn nested_address(pubkey: &[u8]) -> String {
    let h = hash160(pubkey);
    let mut redeem = vec![0x00u8, 0x14];
    redeem.extend_from_slice(&h);
    let sh = hash160(&redeem);
    base58check_encode(0x05, &sh)
}

fn native_segwit_address(pubkey: &[u8]) -> String {
    let h = hash160(pubkey);
    bech32_encode(0, &h, false)
}

fn taproot_address(pubkey: &[u8], secp: &Secp256k1<secp256k1::All>) -> String {
    let x_only = &pubkey[1..33];
    let tag = sha256(b"TapTweak");
    let mut preimage = Vec::with_capacity(64 + 32);
    preimage.extend_from_slice(&tag);
    preimage.extend_from_slice(&tag);
    preimage.extend_from_slice(x_only);
    let tweak = sha256(&preimage);

    let mut x_only_arr = [0u8; 32];
    x_only_arr.copy_from_slice(x_only);
    let xpk = secp256k1::XOnlyPublicKey::from_slice(&x_only_arr).unwrap();
    let (tweaked, _parity) = xpk
        .add_tweak(secp, &secp256k1::Scalar::from_be_bytes(tweak).unwrap())
        .unwrap();

    bech32_encode(1, &tweaked.serialize(), true)
}

fn get_address(pubkey: &[u8], addr_type: AddrType, secp: &Secp256k1<secp256k1::All>) -> String {
    match addr_type {
        AddrType::Legacy => legacy_address(pubkey),
        AddrType::Nested => nested_address(pubkey),
        AddrType::NativeSeg => native_segwit_address(pubkey),
        AddrType::Taproot => taproot_address(pubkey, secp),
    }
}

fn get_all_addresses(pubkey: &[u8], secp: &Secp256k1<secp256k1::All>) -> AllAddresses {
    AllAddresses {
        legacy: legacy_address(pubkey),
        nested: nested_address(pubkey),
        native_segwit: native_segwit_address(pubkey),
        taproot: taproot_address(pubkey, secp),
    }
}

// ── WIF encoding ───────────────────────────────────────────────────────

fn to_wif(privkey_bytes: &[u8; 32]) -> String {
    let mut payload = vec![0x80u8];
    payload.extend_from_slice(privkey_bytes);
    payload.push(0x01); // compressed flag
    let checksum = &sha256(&sha256(&payload))[..4];
    payload.extend_from_slice(checksum);
    base58_encode(&payload)
}

// ── Modular suffix check for base58 (fast path) ───────────────────────

fn base58_suffix_value(suffix: &str) -> (u64, u64) {
    let mut modulus = 1u64;
    let mut target = 0u64;
    for ch in suffix.bytes() {
        let idx = BASE58.iter().position(|&b| b == ch).expect("invalid base58") as u64;
        modulus = modulus.checked_mul(58).expect("suffix too long for u64");
        target = target * 58 + idx;
    }
    (modulus, target)
}

fn check_base58_suffix_fast(
    pubkey: &[u8],
    addr_type: AddrType,
    modulus: u64,
    target: u64,
) -> bool {
    let h = hash160(pubkey);

    let payload: Vec<u8> = match addr_type {
        AddrType::Legacy => {
            let mut p = vec![0x00u8];
            p.extend_from_slice(&h);
            p
        }
        AddrType::Nested => {
            let mut redeem = vec![0x00u8, 0x14];
            redeem.extend_from_slice(&h);
            let sh = hash160(&redeem);
            let mut p = vec![0x05u8];
            p.extend_from_slice(&sh);
            p
        }
        _ => unreachable!(),
    };

    let checksum = &sha256(&sha256(&payload))[..4];
    let mut full = payload;
    full.extend_from_slice(checksum);

    let mut r = 0u64;
    for &byte in full.iter() {
        r = ((r as u128 * 256 + byte as u128) % modulus as u128) as u64;
    }
    r == target
}

// ── Private key offset computation ─────────────────────────────────────

/// Computes (secret_key + offset) mod curve_order
/// Uses simple big-endian byte addition with borrow handling.
fn add_offset_to_secret(start: &[u8; 32], offset: u64) -> [u8; 32] {
    let mut result = *start;
    let mut carry = offset as u128;

    // Add from least significant byte
    for i in (0..32).rev() {
        let sum = result[i] as u128 + (carry & 0xFF);
        result[i] = sum as u8;
        carry = (carry >> 8) + (sum >> 8);
    }
    // If carry overflows, subtract curve order
    // This is rare and we handle it by checking >= n
    if compare_ge_n(&result) {
        subtract_n(&mut result);
    }
    result
}

fn compare_ge_n(bytes: &[u8; 32]) -> bool {
    for i in 0..32 {
        if bytes[i] > CURVE_ORDER[i] {
            return true;
        }
        if bytes[i] < CURVE_ORDER[i] {
            return false;
        }
    }
    true // equal to n
}

fn subtract_n(bytes: &mut [u8; 32]) {
    let mut borrow = 0i128;
    for i in (0..32).rev() {
        let diff = bytes[i] as i128 - CURVE_ORDER[i] as i128 - borrow;
        if diff < 0 {
            bytes[i] = (diff + 256) as u8;
            borrow = 1;
        } else {
            bytes[i] = diff as u8;
            borrow = 0;
        }
    }
}

// ── Validation ─────────────────────────────────────────────────────────

fn is_base58(s: &str) -> bool {
    s.bytes().all(|b| BASE58.contains(&b))
}

fn is_bech32_char(s: &str) -> bool {
    s.bytes()
        .all(|b| b"023456789acdefghjknmpqrstuvwxyz".contains(&b))
}

// ── CLI ────────────────────────────────────────────────────────────────

fn parse_args() -> Result<Config, String> {
    let args: Vec<String> = env::args().collect();
    if args.iter().any(|a| a == "--help" || a == "-h") {
        print_help();
        process::exit(0);
    }

    let mut addr_type = AddrType::Legacy;
    let mut prefix = String::new();
    let mut suffix = String::new();
    let mut threads = None;
    let mut duration = None;
    let mut quiet = false;
    let mut passphrase = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--prefix" => {
                i += 1;
                prefix = args.get(i).cloned().ok_or("--prefix needs a value")?;
            }
            "--suffix" => {
                i += 1;
                suffix = args.get(i).cloned().ok_or("--suffix needs a value")?;
            }
            "--threads" => {
                i += 1;
                let t: usize = args
                    .get(i)
                    .ok_or("--threads needs a value".to_string())
                    .and_then(|s| s.parse().map_err(|e: std::num::ParseIntError| e.to_string()))?;
                threads = Some(t);
            }
            "--duration" => {
                i += 1;
                let d = args.get(i).ok_or("--duration needs a value".to_string())?;
                duration = Some(
                    parse_duration(d).ok_or_else(|| "invalid duration (use 5s, 1m)".to_string())?,
                );
            }
            "--quiet" | "-q" => quiet = true,
            "--passphrase" => {
                i += 1;
                passphrase = Some(args.get(i).cloned().ok_or("--passphrase needs a value".to_string())?);
            }
            other => {
                if let Some(at) = parse_addr_type(other) {
                    addr_type = at;
                } else if !other.starts_with('-') {
                    return Err(format!("unknown argument: {other}"));
                } else {
                    return Err(format!("unknown option: {other}"));
                }
            }
        }
        i += 1;
    }

    if prefix.is_empty() && suffix.is_empty() {
        return Err("at least one of --prefix or --suffix is required".into());
    }

    // Validate patterns
    if !prefix.is_empty() {
        if addr_type.is_bech32() {
            if !is_bech32_char(&prefix) {
                return Err(format!(
                    "invalid bech32 prefix: {:?}. Allowed: 0-9, a-z (no uppercase, no 1/b/i/o)",
                    prefix
                ));
            }
        } else if !is_base58(&prefix) {
            return Err(format!(
                "invalid base58 prefix: {:?}. Allowed: 1-9, A-H, J-N, P-Z, a-k, m-z",
                prefix
            ));
        }
    }
    if !suffix.is_empty() {
        if addr_type.is_bech32() {
            if !is_bech32_char(&suffix) {
                return Err(format!("invalid bech32 suffix: {:?}", suffix));
            }
        } else if !is_base58(&suffix) {
            return Err(format!("invalid base58 suffix: {:?}", suffix));
        }
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
        addr_type,
        prefix,
        suffix,
        threads,
        duration,
        quiet,
        passphrase,
    })
}

fn print_help() {
    println!(
        r#"Bitcoin Vanity Address Generator

Usage:
  btcvanity-rs [type] [options]

Types:
  legacy       P2PKH          (starts with 1)
  nested       P2SH-P2WPKH    (starts with 3)
  native       P2WPKH bech32  (starts with bc1q)
  taproot      P2TR bech32m   (starts with bc1p)

Options:
  --prefix <pat>    Match start of address (after version prefix)
  --suffix <pat>    Match end of address
  --passphrase "x"  Derive starting key from SHA256 of passphrase
  --threads <n>     Worker threads (default: CPU cores)
  --duration <time> Benchmark mode, e.g. 10s, 1m
  --quiet, -q       Less output
  --help, -h        Show help

Optimizations:
  - Incremental key generation (point addition instead of scalar x G)
  - Modular suffix check (avoids full base58 encode for suffix-only search)
  - Batched atomic counters

Examples:
  btcvanity-rs legacy --suffix abc
  btcvanity-rs legacy --prefix Sat
  btcvanity-rs taproot --prefix zen --threads 16
  btcvanity-rs native --suffix fun --passphrase "secret"

Notes:
  - Legacy/Nested: base58 (case-sensitive)
  - Native/Taproot: bech32 (lowercase only)
  - Prefix is checked after the version prefix (1, 3, bc1q, bc1p)
  - Run OFFLINE for security. Your private key = your funds.
"#
    );
}

fn print_banner() {
    println!(
        r#"
   ___                  ___       __    __
  / _ | ___  ___  ___ _/ _ | ___ / /___/ /______ ___ ___
 / __ |/ _ \/ _ \/ _ `/ __ |/ -_) / __/  '_/ -_) -_) _ \
/_/ |_\ .__/ .__/\_,_/_/ |_|\__/_/\__/_/\_\\__/\__/_//_/
     /_/  /_/         Bitcoin Vanity Address Grinder
"#
    );
}

fn print_plan(config: &Config) {
    let charset = config.addr_type.charset_size();
    let prefix_combos: u64 = if config.prefix.is_empty() {
        1
    } else {
        (charset as u64).pow(config.prefix.len() as u32)
    };
    let suffix_combos: u64 = if config.suffix.is_empty() {
        1
    } else {
        (charset as u64).pow(config.suffix.len() as u32)
    };
    let search_space = prefix_combos * suffix_combos;

    let mode = match (config.prefix.is_empty(), config.suffix.is_empty()) {
        (false, false) => format!("prefix {:?} + suffix {:?}", config.prefix, config.suffix),
        (false, true) => format!("prefix {:?}", config.prefix),
        (true, false) => format!("suffix {:?}", config.suffix),
        _ => unreachable!(),
    };

    let type_name = format!("{:?}", config.addr_type).to_lowercase();
    println!("Address type : {}", type_name);
    println!("Target       : {mode}");
    println!("Version pfx  : {}", config.addr_type.version_prefix());
    println!("Threads      : {}", config.threads);
    println!("Search space : {}", search_space);

    let avg = search_space as f64 / 2.0;
    println!("Avg attempts : {:.0}", avg);

    if config.passphrase.is_some() {
        println!("Passphrase   : enabled (deterministic start key)");
    }

    let optimizations =
        if !config.addr_type.is_bech32() && !config.suffix.is_empty() && config.prefix.is_empty() {
            "incremental keygen + modular suffix check"
        } else {
            "incremental keygen"
        };
    println!("Optimizations: {optimizations}");

    if config.duration.is_some() {
        println!("Mode         : benchmark");
    }
    println!("Controls     : Ctrl+C to stop");
    println!();
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

fn hex_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

// ── Worker ─────────────────────────────────────────────────────────────

fn worker(
    id: usize,
    config: &Config,
    stop: &AtomicBool,
    attempts: &AtomicU64,
    tx: &mpsc::Sender<Hit>,
) {
    let secp = Secp256k1::new();
    let mut local_attempts = 0u64;

    // Derive starting secret key
    let start_secret = if let Some(ref pp) = config.passphrase {
        let hash = sha256(pp.as_bytes());
        let offset = (id as u128) * 1_000_000_000_000u128;
        let sk_bytes = add_offset_to_secret(&hash, offset as u64);
        SecretKey::from_slice(&sk_bytes).expect("valid secret from passphrase")
    } else {
        let mut seed = [0u8; 32];
        seed[..8].copy_from_slice(&(id as u64).to_le_bytes());
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        seed[8..16].copy_from_slice(&nanos.to_le_bytes());
        let mut rng = StdRng::from_seed(seed);
        let mut sk_bytes = [0u8; 32];
        loop {
            rng.fill_bytes(&mut sk_bytes);
            if let Ok(sk) = SecretKey::from_slice(&sk_bytes) {
                break sk;
            }
        }
    };

    let start_secret_bytes = start_secret.secret_bytes();

    // Get initial public key
    let mut current_pubkey = PublicKey::from_secret_key(&secp, &start_secret);

    // Generator point for incremental keygen
    let one = SecretKey::from_slice(&[
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 1,
    ])
    .unwrap();
    let generator_pub = PublicKey::from_secret_key(&secp, &one);

    let mut offset: u64 = 0;

    // Pre-compute for fast suffix check (base58 only, suffix-only)
    let use_fast_suffix = !config.addr_type.is_bech32()
        && !config.suffix.is_empty()
        && config.prefix.is_empty()
        && config.suffix.len() <= 10;

    let (suffix_mod, suffix_target) = if use_fast_suffix {
        let (m, t) = base58_suffix_value(&config.suffix);
        (Some(m), Some(t))
    } else {
        (None, None)
    };

    // Pre-compute prefix/suffix matchers (after version prefix)
    let prefix_pat = if config.prefix.is_empty() {
        String::new()
    } else if config.addr_type.is_bech32() {
        config.prefix.to_lowercase()
    } else {
        config.prefix.clone()
    };
    let suffix_pat = if config.suffix.is_empty() {
        String::new()
    } else if config.addr_type.is_bech32() {
        config.suffix.to_lowercase()
    } else {
        config.suffix.clone()
    };
    let version_prefix_len = config.addr_type.version_prefix().len();

    loop {
        if local_attempts & 1023 == 0 && stop.load(Ordering::Relaxed) {
            break;
        }

        let pubkey_bytes = current_pubkey.serialize();

        let matched = if use_fast_suffix {
            check_base58_suffix_fast(
                &pubkey_bytes,
                config.addr_type,
                suffix_mod.unwrap(),
                suffix_target.unwrap(),
            )
        } else {
            let addr = get_address(&pubkey_bytes, config.addr_type, &secp);
            let after_version = &addr[version_prefix_len..];

            let prefix_ok = prefix_pat.is_empty() || after_version.starts_with(prefix_pat.as_str());
            let suffix_ok = suffix_pat.is_empty() || addr.ends_with(suffix_pat.as_str());

            prefix_ok && suffix_ok
        };

        local_attempts += 1;
        if local_attempts >= 16_384 {
            attempts.fetch_add(local_attempts, Ordering::Relaxed);
            local_attempts = 0;
        }

        if matched {
            let total = attempts.fetch_add(local_attempts, Ordering::Relaxed) + local_attempts;

            // Re-derive the actual private key: start_secret + offset (mod n)
            let actual_sk_bytes = add_offset_to_secret(&start_secret_bytes, offset);
            let actual_privkey = SecretKey::from_slice(&actual_sk_bytes).expect("valid privkey");
            let actual_pubkey = PublicKey::from_secret_key(&secp, &actual_privkey);
            let actual_pubkey_bytes = actual_pubkey.serialize();
            let address = get_address(&actual_pubkey_bytes, config.addr_type, &secp);
            let all = get_all_addresses(&actual_pubkey_bytes, &secp);
            let pk_bytes = actual_privkey.secret_bytes();

            let _ = tx.send(Hit {
                address,
                wif: to_wif(&pk_bytes),
                privkey_hex: hex_bytes(&pk_bytes),
                pubkey_hex: hex_bytes(&actual_pubkey_bytes),
                all_addresses: all,
                attempts: total,
            });
            stop.store(true, Ordering::Relaxed);
            break;
        }

        // Increment public key via point addition: P_next = P_current + G
        offset += 1;
        match current_pubkey.combine(&generator_pub) {
            Ok(next) => current_pubkey = next,
            Err(_) => {
                // Overflow: start fresh with new random key
                let mut rng = StdRng::from_entropy();
                let mut sk_bytes = [0u8; 32];
                loop {
                    rng.fill_bytes(&mut sk_bytes);
                    if let Ok(sk) = SecretKey::from_slice(&sk_bytes) {
                        current_pubkey = PublicKey::from_secret_key(&secp, &sk);
                        break;
                    }
                }
                offset = 0;
            }
        }
    }

    if local_attempts > 0 {
        attempts.fetch_add(local_attempts, Ordering::Relaxed);
    }
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

        thread::spawn(move || {
            worker(id, &config, &stop, &attempts, &tx);
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
                print_hit(&hit, start.elapsed(), config.threads, &config);
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
    let charset = config.addr_type.charset_size();
    let pattern_len = config.prefix.len() + config.suffix.len();
    let search_space = (charset as f64).powi(pattern_len as i32);
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

fn print_hit(hit: &Hit, elapsed: Duration, threads: usize, config: &Config) {
    let secs = elapsed.as_secs_f64().max(0.001);
    let rate = hit.attempts as f64 / secs;
    let type_name = format!("{:?}", config.addr_type).to_lowercase();

    println!("{}", "=".repeat(64));
    println!("MATCH FOUND!");
    println!("{}", "=".repeat(64));
    println!("Address type : {}", type_name);
    println!("Address      : {}", hit.address);
    println!("Private (WIF): {}", hit.wif);
    println!("Private (hex): {}", hit.privkey_hex);
    println!("Public key   : {}", hit.pubkey_hex);
    println!("Attempts     : {}", hit.attempts);
    println!("Time         : {}", format_duration(elapsed));
    println!("Speed        : {:.0} keys/sec ({} threads)", rate, threads);
    println!("{}", "=".repeat(64));

    println!("\nAll addresses for this keypair:");
    println!("  Legacy (P2PKH)      : {}", hit.all_addresses.legacy);
    println!(
        "  Nested SegWit (P2SH): {}",
        hit.all_addresses.nested
    );
    println!(
        "  Native SegWit       : {}",
        hit.all_addresses.native_segwit
    );
    println!("  Taproot (P2TR)      : {}", hit.all_addresses.taproot);
    println!();
}
