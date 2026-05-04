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
git clone https://github.com/YourUsername/ApnaAddress.git
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

## Time Estimates

The tool shows estimated time before starting. General guide for **1 CPU thread**:

| Pattern Length | ETH (~15k keys/sec) | BTC (~15k keys/sec) | SOL (~2.5k keys/sec) |
|---------------|---------------------|---------------------|----------------------|
| 2 chars | instant | instant | ~1s |
| 3 chars | ~0.1s | ~6s | ~39s |
| 4 chars | ~2s | ~6min | ~37min |
| 5 chars | ~35s | ~5.5h | ~1.5 days |
| 6 chars | ~9min | ~13 days | ~87 days |

Combining prefix + suffix multiplies the search spaces together.

More threads = proportionally faster. 8 threads ≈ 8x speed.

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
