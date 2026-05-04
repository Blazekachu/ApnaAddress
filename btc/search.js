const { Worker } = require('worker_threads');
const os = require('os');
const path = require('path');
const crypto = require('crypto');

const typeMap = {
  legacy: 'legacy', p2pkh: 'legacy',
  nested: 'nested', 'nested-segwit': 'nested', p2sh: 'nested',
  native: 'nativeSegwit', 'native-segwit': 'nativeSegwit', segwit: 'nativeSegwit', p2wpkh: 'nativeSegwit',
  taproot: 'taproot', p2tr: 'taproot',
};

const args = process.argv.slice(2);

if (args.length === 0 || args.includes('--help') || args.includes('-h')) {
  console.log(`
Optimized Bitcoin Vanity Address Generator

Usage:
  node search.js [type] [options]

Types:
  legacy    - P2PKH (starts with 1)
  nested    - P2SH-P2WPKH (starts with 3)
  native    - P2WPKH bech32 (starts with bc1q)
  taproot   - P2TR bech32m (starts with bc1p)

Options:
  --prefix <pat>    Match start of address (after version prefix)
  --suffix <pat>    Match end of address
  --passphrase "x"  Derive starting key from SHA256 of passphrase
  --threads N       Number of worker threads (default: CPU cores - 1)

You can use --prefix and --suffix together to match both.

Optimizations:
  - Incremental key generation (point addition instead of scalar multiplication)
  - Modular base58 suffix check (avoids full encoding, suffix-only mode)
  - Pre-allocated buffers (reduced GC pressure)

Examples:
  node search.js legacy --suffix abc
  node search.js legacy --prefix Sat
  node search.js legacy --prefix Sat --suffix BTC
  node search.js taproot --prefix zen --passphrase "mysecret"

Notes:
  - Run OFFLINE for security. Your private key = your funds.
  - Legacy/Nested: base58 (case-sensitive)
  - Native/Taproot: bech32 (lowercase only)
  - Prefix skips version prefix (1, 3, bc1q, bc1p)
`);
  process.exit(0);
}

// Parse options
let prefix = null;
let suffix = null;
let passphrase = null;
let threadCount = null;
let type = 'legacy';

for (let i = 0; i < args.length; i++) {
  if (args[i] === '--prefix') {
    prefix = args[++i];
  } else if (args[i] === '--suffix') {
    suffix = args[++i];
  } else if (args[i] === '--passphrase') {
    passphrase = args[++i];
  } else if (args[i] === '--threads') {
    threadCount = parseInt(args[++i], 10);
  } else if (typeMap[args[i].toLowerCase()]) {
    type = args[i].toLowerCase();
  }
}

const addrKey = typeMap[type];

if (!addrKey) {
  console.error(`Unknown type: ${type}`);
  console.error('Valid types: legacy, nested, native, taproot');
  process.exit(1);
}

if (!prefix && !suffix) {
  console.error('Error: at least one of --prefix or --suffix required');
  process.exit(1);
}

const isBech32 = addrKey === 'nativeSegwit' || addrKey === 'taproot';
const base58Regex = /^[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]+$/;
const bech32Regex = /^[02-9ac-hj-np-z]+$/;

// Validate patterns
function validatePattern(pat, label) {
  if (!pat) return;
  if (isBech32) {
    if (!bech32Regex.test(pat)) {
      console.error(`Invalid bech32 ${label}: "${pat}". Allowed: 0-9 a-c d-f g-h j-k l-n p q r-t u-w x-z`);
      process.exit(1);
    }
  } else {
    if (!base58Regex.test(pat)) {
      console.error(`Invalid base58 ${label}: "${pat}". Allowed: 1-9 A-H J-N P-Z a-k m-z`);
      process.exit(1);
    }
  }
}
validatePattern(prefix, 'prefix');
validatePattern(suffix, 'suffix');

// Derive starting key from passphrase if provided
let startKey = null;
if (passphrase) {
  startKey = crypto.createHash('sha256').update(passphrase).digest().toString('hex');
}

// Estimate difficulty
const charsetSize = isBech32 ? 32 : 58;
const prefixCombinations = prefix ? Math.pow(charsetSize, prefix.length) : 1;
const suffixCombinations = suffix ? Math.pow(charsetSize, suffix.length) : 1;
const combinations = prefixCombinations * suffixCombinations;
const avgAttempts = Math.floor(combinations / 2);

const numWorkers = threadCount || Math.max(1, os.cpus().length - 1);

// Estimate time
function formatTime(seconds) {
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${seconds % 60}s`;
  if (seconds < 86400) return `${(seconds / 3600).toFixed(1)}h`;
  return `${(seconds / 86400).toFixed(1)} days`;
}

// ~15,000 keys/sec per thread for BTC (based on benchmarks)
const SINGLE_THREAD_RATE = 15000;
const singleThreadTime = Math.floor(avgAttempts / SINGLE_THREAD_RATE);
const multiThreadTime = Math.floor(avgAttempts / (SINGLE_THREAD_RATE * numWorkers));

let modeLabel = '';
if (prefix && suffix) modeLabel = `prefix "${prefix}" + suffix "${suffix}"`;
else if (prefix) modeLabel = `prefix "${prefix}"`;
else modeLabel = `suffix "${suffix}"`;

console.log(`\nSearching for ${type} address with ${modeLabel}...`);
if (passphrase) console.log(`Passphrase: enabled (deterministic start key)`);
console.log(`Charset: ${isBech32 ? 'bech32' : 'base58'} | Search space: ${combinations.toLocaleString()} | Avg attempts: ${avgAttempts.toLocaleString()}`);
console.log(`Est. time (1 thread) : ~${formatTime(singleThreadTime)}`);
console.log(`Est. time (${numWorkers} threads): ~${formatTime(multiThreadTime)}`);
console.log(`Using ${numWorkers} worker threads (${os.cpus().length} cores detected)`);
console.log(`Optimizations: incremental keygen${!isBech32 && suffix && !prefix ? ' + modular suffix check' : ''}`);
console.log('Press Ctrl+C to stop.\n');

const startTime = Date.now();
let totalAttempts = 0;
let found = false;
const workers = [];

for (let i = 0; i < numWorkers; i++) {
  const worker = new Worker(path.join(__dirname, 'worker.js'), {
    workerData: { prefix, suffix, addrKey, startKey, workerId: i },
  });
  workers.push(worker);

  worker.on('message', (msg) => {
    if (msg.type === 'progress') {
      totalAttempts += msg.attempts;
      const elapsed = (Date.now() - startTime) / 1000;
      const rate = Math.floor(totalAttempts / elapsed);
      const remaining = Math.max(0, avgAttempts - totalAttempts);
      const etaSec = rate > 0 ? Math.floor(remaining / rate) : 0;
      const eta = etaSec > 3600
        ? `${(etaSec / 3600).toFixed(1)}h`
        : etaSec > 60
          ? `${Math.floor(etaSec / 60)}m ${etaSec % 60}s`
          : `${etaSec}s`;
      console.log(`  ... ${totalAttempts.toLocaleString()} attempts | ${rate.toLocaleString()} keys/sec | ETA ~${eta}`);
    }

    if (msg.type === 'found' && !found) {
      found = true;
      totalAttempts += msg.attempts;
      const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
      const rate = Math.floor(totalAttempts / elapsed);

      console.log('='.repeat(60));
      console.log('MATCH FOUND!');
      console.log('='.repeat(60));
      console.log(`Address Type : ${type}`);
      console.log(`Address      : ${msg.address}`);
      console.log(`Private Key  : ${msg.wif}`);
      console.log(`Public Key   : ${msg.pubkey}`);
      console.log(`Attempts     : ${totalAttempts.toLocaleString()}`);
      console.log(`Time         : ${elapsed}s`);
      console.log(`Speed        : ${rate.toLocaleString()} keys/sec (${numWorkers} threads)`);
      console.log('='.repeat(60));
      console.log('\nAll addresses for this keypair:');
      console.log(`  Legacy (P2PKH)      : ${msg.addresses.legacy}`);
      console.log(`  Nested SegWit (P2SH): ${msg.addresses.nested}`);
      console.log(`  Native SegWit       : ${msg.addresses.nativeSegwit}`);
      console.log(`  Taproot (P2TR)      : ${msg.addresses.taproot}`);
      console.log();

      for (const w of workers) w.terminate();
      process.exit(0);
    }
  });

  worker.on('error', (err) => {
    console.error(`Worker ${i} error:`, err.message);
  });
}
