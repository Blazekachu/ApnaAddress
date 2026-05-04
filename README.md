# Apna Address

Vanity address generator for Bitcoin, Ethereum, and Solana. Find custom wallet addresses with your chosen prefix, suffix, or both.

**Runs entirely offline. Nothing is saved to disk. Keys only appear in your terminal.**

## Supported Chains

| Chain | Folder | Address Types | Optimization |
|-------|--------|---------------|--------------|
| Bitcoin | `btc/` | Legacy, Nested SegWit, Native SegWit, Taproot | Incremental keygen (point addition) |
| Ethereum | `eth/` | EVM (EIP-55 checksum) | Incremental keygen (same secp256k1 curve) |
| Solana | `sol/` | Ed25519 base58 | Fresh keypair per attempt |

## Requirements

- Node.js v18+
- Run `npm install` inside each chain folder before use

## Setup

```bash
git clone https://github.com/Blazekachu/ApnaAddress.git
cd ApnaAddress

# Install dependencies for the chain you want
cd btc && npm install && cd ..
cd eth && npm install && cd ..
cd sol && npm install && cd ..
```

## Usage

### Bitcoin

```bash
cd btc

# Suffix only
node search.js legacy --suffix abc

# Prefix only (after version prefix 1, 3, bc1q, bc1p)
node search.js legacy --prefix Sat

# Both prefix and suffix
node search.js legacy --prefix Sat --suffix BTC

# Taproot with passphrase
node search.js taproot --prefix zen --passphrase "your secret"

# Control thread count
node search.js legacy --prefix Hi --threads 4
```

**Address types:** `legacy` (1...), `nested` (3...), `native` (bc1q...), `taproot` (bc1p...)

**Charset:** Legacy/Nested use base58 (case-sensitive). Native/Taproot use bech32 (lowercase only).

### Ethereum

```bash
cd eth

# Prefix only (after 0x)
node search.js --prefix dead

# Suffix only
node search.js --suffix cafe

# Both prefix and suffix
node search.js --prefix 420 --suffix 69

# With EIP-55 checksum matching (case-sensitive)
node search.js --prefix Ab --checksum

# With passphrase
node search.js --prefix beef --passphrase "your secret"
```

**Charset:** Hex (0-9, a-f). Case-insensitive by default, use `--checksum` for exact case.

### Solana

```bash
cd sol

# Prefix only
node search.js --prefix pump

# Suffix only
node search.js --suffix sol

# Both prefix and suffix
node search.js --prefix 42 --suffix 69

# With passphrase
node search.js --prefix dex --passphrase "your secret"
```

**Charset:** Base58 (1-9, A-H, J-N, P-Z, a-k, m-z). Case-sensitive.

## Options (all chains)

| Option | Description |
|--------|-------------|
| `--prefix <pat>` | Match start of address |
| `--suffix <pat>` | Match end of address |
| `--passphrase "x"` | Derive starting key from SHA256 of passphrase |
| `--threads N` | Number of CPU threads (default: cores - 1) |
| `--checksum` | ETH only: EIP-55 case-sensitive matching |

You can combine `--prefix` and `--suffix` to match both simultaneously.

## What Can This Tool Do?

Estimated times by pattern length and CPU threads. These are averages — actual time varies with luck.

### Ethereum (hex charset, ~15k keys/sec per thread)

| Pattern | 1 thread | 4 threads | 8 threads | 16 threads |
|---------|----------|-----------|-----------|------------|
| 2 chars | instant | instant | instant | instant |
| 3 chars | instant | instant | instant | instant |
| 4 chars | ~2s | instant | instant | instant |
| 5 chars | ~35s | ~9s | ~4s | ~2s |
| 6 chars | ~9 min | ~2 min | ~1 min | ~34s |
| 7 chars | ~2.5 hrs | ~37 min | ~19 min | ~9 min |
| 8 chars | ~1.6 days | ~10 hrs | ~5 hrs | ~2.5 hrs |

### Bitcoin (base58 charset, ~15k keys/sec per thread)

| Pattern | 1 thread | 4 threads | 8 threads | 16 threads |
|---------|----------|-----------|-----------|------------|
| 2 chars | instant | instant | instant | instant |
| 3 chars | ~6s | ~2s | instant | instant |
| 4 chars | ~6 min | ~1.5 min | ~45s | ~22s |
| 5 chars | ~5.5 hrs | ~1.4 hrs | ~41 min | ~21 min |
| 6 chars | ~13 days | ~3.3 days | ~1.6 days | ~20 hrs |

### Solana (base58 charset, ~2.5k keys/sec per thread)

| Pattern | 1 thread | 4 threads | 8 threads | 16 threads |
|---------|----------|-----------|-----------|------------|
| 2 chars | ~1s | instant | instant | instant |
| 3 chars | ~39s | ~10s | ~5s | ~2s |
| 4 chars | ~37 min | ~9 min | ~5 min | ~2 min |
| 5 chars | ~1.5 days | ~9 hrs | ~4.5 hrs | ~2.2 hrs |
| 6 chars | ~87 days | ~22 days | ~11 days | ~5.4 days |

### Prefix + Suffix Combined

Search spaces multiply. Example: 3-char prefix + 2-char suffix = same difficulty as 5 chars.

## Need More Speed? Use GPU Tools

This tool is CPU-only. For heavy patterns (6+ chars on BTC/SOL, 8+ on ETH), a GPU is significantly faster.

| Tool | Chain | GPU Speed (RTX 4090) | vs Our CPU (8 threads) |
|------|-------|---------------------|----------------------|
| [VanitySearch](https://github.com/JeanLucPons/VanitySearch) (C++) | BTC | ~1B keys/sec | ~8,300x faster |
| [Profanity2](https://github.com/1inch/profanity2) (OpenCL) | ETH | ~1.5B keys/sec | ~12,500x faster |
| [Solana Vanity](https://github.com/nicholasgasior/solana-vanity-grinder) (Rust) | SOL | ~10M keys/sec | ~500x faster |

**When to use GPU tools:** if the estimated time on this tool exceeds a few hours, a GPU tool will get the job done in seconds or minutes.

**When this tool is enough:** patterns up to 5 chars (ETH/BTC) or 4 chars (SOL) finish quickly on any modern CPU.

## Passphrase Mode

When you use `--passphrase`, the starting private key is derived from `SHA256(your passphrase)` instead of being random.

**With 1 thread** (`--threads 1`): same passphrase + same pattern = same result every time (deterministic).

**With multiple threads**: each thread searches a different region, so whichever finds a match first is non-deterministic (different result each run).

## Security

- Runs 100% offline. No network calls.
- Nothing written to disk. No logs, no temp files.
- Keys exist only in RAM during execution.
- Output goes to stdout only — clear your terminal after copying your key.
- Always verify: import the private key into your wallet and confirm the address matches before using it.
- Source code is fully readable — audit it yourself.

## Output Example

```
Searching for ETH address with prefix "420" + suffix "69"...
Search space: 10,48,576 | Avg attempts: 5,24,288
Est. time (1 thread) : ~34s
Est. time (7 threads): ~5s
Using 7 worker threads (8 cores detected)
Optimizations: incremental keygen (secp256k1 point addition)
Press Ctrl+C to stop.

  ... 2,34,567 attempts | 16,234 keys/sec | ETA ~18s
============================================================
MATCH FOUND!
============================================================
Address      : 0x4205...d169
Private Key  : 0xabc123...
Public Key   : 02def456...
Attempts     : 4,56,789
Time         : 28.1s
Speed        : 16,250 keys/sec (7 threads)
============================================================
```

## License

MIT
