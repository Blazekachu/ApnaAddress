const { Worker } = require('worker_threads');
const os = require('os');
const path = require('path');
const crypto = require('crypto');

const args = process.argv.slice(2);

if (args.length === 0 || args.includes('--help') || args.includes('-h')) {
  console.log(`
Optimized Ethereum Vanity Address Generator

Usage:
  node search.js [options]

Options:
  --prefix <pat>    Match start of address (after 0x)
  --suffix <pat>    Match end of address
  --passphrase "x"  Derive starting key from SHA256 of passphrase
  --threads N       Number of worker threads (default: CPU cores - 1)
  --checksum        Match with EIP-55 checksum case (default: case-insensitive)

You can use --prefix and --suffix together to match both.

Optimizations:
  - Incremental key generation (point addition, same curve as Bitcoin)
  - Pre-allocated buffers (reduced GC pressure)

Examples:
  node search.js --prefix dead
  node search.js --suffix cafe
  node search.js --prefix 420 --suffix 69
  node search.js --prefix b00b --passphrase "mysecret"

Notes:
  - Run OFFLINE for security. Your private key = your funds.
  - ETH addresses are hex (0-9, a-f), case-insensitive by default.
  - Use --checksum for EIP-55 mixed-case matching.
  - Nothing is saved to disk. Output goes to stdout only.
`);
  process.exit(0);
}

// Parse options
let prefix = null;
let suffix = null;
let passphrase = null;
let threadCount = null;
let checksumMode = false;

for (let i = 0; i < args.length; i++) {
  if (args[i] === '--prefix') {
    prefix = args[++i];
  } else if (args[i] === '--suffix') {
    suffix = args[++i];
  } else if (args[i] === '--passphrase') {
    passphrase = args[++i];
  } else if (args[i] === '--threads') {
    threadCount = parseInt(args[++i], 10);
  } else if (args[i] === '--checksum') {
    checksumMode = true;
  }
}

if (!prefix && !suffix) {
  console.error('Error: at least one of --prefix or --suffix required');
  process.exit(1);
}

// Validate hex patterns
const hexChars = /^[0-9a-fA-F]+$/;
if (prefix && !hexChars.test(prefix)) {
  console.error(`Invalid hex prefix: "${prefix}". Allowed: 0-9, a-f, A-F`);
  process.exit(1);
}
if (suffix && !hexChars.test(suffix)) {
  console.error(`Invalid hex suffix: "${suffix}". Allowed: 0-9, a-f, A-F`);
  process.exit(1);
}

// Derive starting key from passphrase if provided
let startKey = null;
if (passphrase) {
  startKey = crypto.createHash('sha256').update(passphrase).digest().toString('hex');
}

// Estimate difficulty
const charsetSize = 16;
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

// ~15,000 keys/sec per thread for ETH (based on benchmarks)
const SINGLE_THREAD_RATE = 15000;
const singleThreadTime = Math.floor(avgAttempts / SINGLE_THREAD_RATE);
const multiThreadTime = Math.floor(avgAttempts / (SINGLE_THREAD_RATE * numWorkers));

let modeLabel = '';
if (prefix && suffix) modeLabel = `prefix "${prefix}" + suffix "${suffix}"`;
else if (prefix) modeLabel = `prefix "${prefix}"`;
else modeLabel = `suffix "${suffix}"`;

console.log(`\nSearching for ETH address with ${modeLabel}${checksumMode ? ' (checksum)' : ''}...`);
if (passphrase) console.log(`Passphrase: enabled (deterministic start key)`);
console.log(`Search space: ${combinations.toLocaleString()} | Avg attempts: ${avgAttempts.toLocaleString()}`);
console.log(`Est. time (1 thread) : ~${formatTime(singleThreadTime)}`);
console.log(`Est. time (${numWorkers} threads): ~${formatTime(multiThreadTime)}`);
console.log(`Using ${numWorkers} worker threads (${os.cpus().length} cores detected)`);
console.log(`Optimizations: incremental keygen (secp256k1 point addition)`);
console.log('Press Ctrl+C to stop.\n');

const startTime = Date.now();
let totalAttempts = 0;
let found = false;
const workers = [];

for (let i = 0; i < numWorkers; i++) {
  const worker = new Worker(path.join(__dirname, 'worker.js'), {
    workerData: { prefix, suffix, startKey, checksumMode, workerId: i },
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
      console.log(`Public Key   : ${msg.pubkey}`);
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
