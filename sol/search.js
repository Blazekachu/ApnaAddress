const { Worker } = require('worker_threads');
const os = require('os');
const path = require('path');
const crypto = require('crypto');

const args = process.argv.slice(2);

if (args.length === 0 || args.includes('--help') || args.includes('-h')) {
  console.log(`
Optimized Solana Vanity Address Generator

Usage:
  node search.js [options]

Options:
  --prefix <pat>    Match start of address
  --suffix <pat>    Match end of address
  --passphrase "x"  Derive starting seed from SHA256 of passphrase
  --threads N       Number of worker threads (default: CPU cores - 1)

You can use --prefix and --suffix together to match both.

Notes:
  - Solana uses Ed25519 curve (no incremental keygen shortcut).
  - Each attempt generates a fresh random keypair.
  - Addresses are base58 encoded (1-9, A-H, J-N, P-Z, a-k, m-z).
  - Run OFFLINE for security. Your private key = your funds.
  - Nothing is saved to disk. Output goes to stdout only.

Examples:
  node search.js --prefix pump
  node search.js --suffix sol
  node search.js --prefix 42 --suffix 69
  node search.js --prefix dex --passphrase "mysecret"
`);
  process.exit(0);
}

// Parse options
let prefix = null;
let suffix = null;
let passphrase = null;
let threadCount = null;

for (let i = 0; i < args.length; i++) {
  if (args[i] === '--prefix') {
    prefix = args[++i];
  } else if (args[i] === '--suffix') {
    suffix = args[++i];
  } else if (args[i] === '--passphrase') {
    passphrase = args[++i];
  } else if (args[i] === '--threads') {
    threadCount = parseInt(args[++i], 10);
  }
}

if (!prefix && !suffix) {
  console.error('Error: at least one of --prefix or --suffix required');
  process.exit(1);
}

// Validate base58 patterns
const base58Chars = /^[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]+$/;
if (prefix && !base58Chars.test(prefix)) {
  console.error(`Invalid base58 prefix: "${prefix}". Allowed: 1-9 A-H J-N P-Z a-k m-z (no 0, I, O, l)`);
  process.exit(1);
}
if (suffix && !base58Chars.test(suffix)) {
  console.error(`Invalid base58 suffix: "${suffix}". Allowed: 1-9 A-H J-N P-Z a-k m-z (no 0, I, O, l)`);
  process.exit(1);
}

// Derive seed from passphrase if provided
let seed = null;
if (passphrase) {
  seed = crypto.createHash('sha256').update(passphrase).digest().toString('hex');
}

// Estimate difficulty
const charsetSize = 58;
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

// ~2,500 keys/sec per thread for SOL (Ed25519, based on benchmarks)
const SINGLE_THREAD_RATE = 2500;
const singleThreadTime = Math.floor(avgAttempts / SINGLE_THREAD_RATE);
const multiThreadTime = Math.floor(avgAttempts / (SINGLE_THREAD_RATE * numWorkers));

let modeLabel = '';
if (prefix && suffix) modeLabel = `prefix "${prefix}" + suffix "${suffix}"`;
else if (prefix) modeLabel = `prefix "${prefix}"`;
else modeLabel = `suffix "${suffix}"`;

console.log(`\nSearching for SOL address with ${modeLabel}...`);
if (passphrase) console.log(`Passphrase: enabled (deterministic seed)`);
console.log(`Search space: ${combinations.toLocaleString()} | Avg attempts: ${avgAttempts.toLocaleString()}`);
console.log(`Est. time (1 thread) : ~${formatTime(singleThreadTime)}`);
console.log(`Est. time (${numWorkers} threads): ~${formatTime(multiThreadTime)}`);
console.log(`Using ${numWorkers} worker threads (${os.cpus().length} cores detected)`);
console.log(`Note: Ed25519 requires fresh keypair per attempt (no incremental shortcut)`);
console.log('Press Ctrl+C to stop.\n');

const startTime = Date.now();
let totalAttempts = 0;
let found = false;
const workers = [];

for (let i = 0; i < numWorkers; i++) {
  const worker = new Worker(path.join(__dirname, 'worker.js'), {
    workerData: { prefix, suffix, seed, workerId: i },
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
      console.log(`Address      : ${msg.address}`);
      console.log(`Private Key  : ${msg.privkey}`);
      console.log(`Keypair (bs58): ${msg.keypair}`);
      console.log(`Attempts     : ${totalAttempts.toLocaleString()}`);
      console.log(`Time         : ${elapsed}s`);
      console.log(`Speed        : ${rate.toLocaleString()} keys/sec (${numWorkers} threads)`);
      console.log('='.repeat(60));
      console.log();

      for (const w of workers) w.terminate();
      process.exit(0);
    }
  });

  worker.on('error', (err) => {
    console.error(`Worker ${i} error:`, err.message);
  });
}
