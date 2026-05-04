const { parentPort, workerData } = require('worker_threads');
const crypto = require('crypto');

const { prefix, suffix, seed, workerId } = workerData;

// ── Base58 encoding (Solana uses raw base58, no checksum) ──
const BASE58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

function base58Encode(bytes) {
  let num = 0n;
  for (const b of bytes) num = num * 256n + BigInt(b);
  const chars = [];
  while (num > 0n) {
    chars.unshift(BASE58[Number(num % 58n)]);
    num /= 58n;
  }
  for (const b of bytes) {
    if (b === 0) chars.unshift('1');
    else break;
  }
  return chars.join('');
}

// ── Ed25519 keypair generation using Node's native crypto ──
function generateKeypair(seedBytes) {
  if (seedBytes) {
    const privKey = crypto.createPrivateKey({
      key: Buffer.concat([
        Buffer.from('302e020100300506032b657004220420', 'hex'),
        seedBytes,
      ]),
      format: 'der',
      type: 'pkcs8',
    });
    const pubKey = crypto.createPublicKey(privKey);
    const pubRaw = pubKey.export({ type: 'spki', format: 'der' }).subarray(12);
    return { privateKey: seedBytes, publicKey: pubRaw };
  } else {
    const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
    const privRaw = privateKey.export({ type: 'pkcs8', format: 'der' }).subarray(16);
    const pubRaw = publicKey.export({ type: 'spki', format: 'der' }).subarray(12);
    return { privateKey: privRaw, publicKey: pubRaw };
  }
}

// ── Deterministic seed derivation for passphrase mode ──
let baseSeed = null;
let counter = 0n;

if (seed) {
  baseSeed = Buffer.from(seed, 'hex');
  counter = BigInt(workerId) * BigInt('1000000000000');
}

function nextSeed() {
  const counterBuf = Buffer.alloc(8);
  counterBuf.writeBigUInt64BE(counter);
  counter++;
  return crypto.createHash('sha256').update(Buffer.concat([baseSeed, counterBuf])).digest();
}

let attempts = 0;
let lastReport = Date.now();

// ── Main loop ──
while (true) {
  let kp;
  if (baseSeed) {
    const s = nextSeed();
    kp = generateKeypair(s);
  } else {
    kp = generateKeypair(null);
  }

  const address = base58Encode(kp.publicKey);

  const prefixOk = !prefix || address.startsWith(prefix);
  const suffixOk = !suffix || address.endsWith(suffix);
  const matched = prefixOk && suffixOk;

  attempts++;

  if (matched) {
    const fullKeypair = Buffer.concat([kp.privateKey, kp.publicKey]);

    parentPort.postMessage({
      type: 'found',
      address,
      privkey: Buffer.from(kp.privateKey).toString('hex'),
      keypair: base58Encode(fullKeypair),
      attempts,
    });
    break;
  }

  const now = Date.now();
  if (now - lastReport >= 3000) {
    parentPort.postMessage({ type: 'progress', attempts });
    lastReport = now;
    attempts = 0;
  }
}
