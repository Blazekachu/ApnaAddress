const { parentPort, workerData } = require('worker_threads');
const crypto = require('crypto');
const ecc = require('tiny-secp256k1');
const keccak256 = require('keccak256');

const { prefix, suffix, startKey, checksumMode, workerId } = workerData;

// ── Generator point G (for incremental keygen) ──
const ONE = Buffer.alloc(32);
ONE[31] = 1;
const G_POINT = Buffer.from(ecc.pointFromScalar(ONE, true));

// ── EIP-55 checksum encoding ──
function toChecksumAddress(addrHex) {
  const hash = keccak256(Buffer.from(addrHex, 'ascii')).toString('hex');
  let result = '0x';
  for (let i = 0; i < 40; i++) {
    if (parseInt(hash[i], 16) >= 8) {
      result += addrHex[i].toUpperCase();
    } else {
      result += addrHex[i].toLowerCase();
    }
  }
  return result;
}

// ── ETH address from compressed pubkey ──
function getEthAddress(compressedPubkey) {
  const uncompressed = Buffer.from(ecc.pointCompress(compressedPubkey, false));
  // Keccak256 of the 64-byte public key (without 04 prefix)
  const hash = keccak256(uncompressed.subarray(1));
  // Last 20 bytes
  return hash.subarray(12).toString('hex');
}

// ── Pre-compute lowercase patterns ──
const prefixLower = prefix ? prefix.toLowerCase() : null;
const suffixLower = suffix ? suffix.toLowerCase() : null;

// ── Initialize starting point ──
let startPrivKey;
if (startKey) {
  startPrivKey = Buffer.from(startKey, 'hex');
  if (workerId > 0) {
    const offsetBuf = Buffer.alloc(32);
    const stride = BigInt(workerId) * BigInt('1000000000000');
    for (let i = 7; i >= 0; i--) {
      offsetBuf[24 + i] = Number((stride >> BigInt((7 - i) * 8)) & 0xFFn);
    }
    startPrivKey = Buffer.from(ecc.privateAdd(startPrivKey, offsetBuf));
  }
} else {
  startPrivKey = crypto.randomBytes(32);
}
while (!ecc.isPrivate(startPrivKey)) {
  startPrivKey = crypto.randomBytes(32);
}
let currentPubKey = Buffer.from(ecc.pointFromScalar(startPrivKey, true));
let offset = 0;

let attempts = 0;
let lastReport = Date.now();

// ── Main loop ──
while (true) {
  const addrHex = getEthAddress(currentPubKey);
  let matched = false;

  if (checksumMode) {
    const checksumAddr = toChecksumAddress(addrHex);
    const addrBody = checksumAddr.substring(2);
    const prefixOk = !prefix || addrBody.startsWith(prefix);
    const suffixOk = !suffix || addrBody.endsWith(suffix);
    matched = prefixOk && suffixOk;
  } else {
    const prefixOk = !prefixLower || addrHex.startsWith(prefixLower);
    const suffixOk = !suffixLower || addrHex.endsWith(suffixLower);
    matched = prefixOk && suffixOk;
  }

  attempts++;
  offset++;

  if (matched) {
    const offsetBuf = Buffer.alloc(32);
    const off = BigInt(offset - 1);
    for (let i = 7; i >= 0; i--) {
      offsetBuf[24 + i] = Number((off >> BigInt((7 - i) * 8)) & 0xFFn);
    }
    const privKey = Buffer.from(ecc.privateAdd(startPrivKey, offsetBuf));
    const pubkey = Buffer.from(ecc.pointFromScalar(privKey, true));
    const finalAddr = getEthAddress(pubkey);
    const checksumAddr = toChecksumAddress(finalAddr);

    parentPort.postMessage({
      type: 'found',
      address: checksumAddr,
      privkey: '0x' + Buffer.from(privKey).toString('hex'),
      pubkey: Buffer.from(pubkey).toString('hex'),
      attempts,
    });
    break;
  }

  // Increment public key: P_next = P_current + G
  const next = ecc.pointAdd(currentPubKey, G_POINT, true);
  if (!next) {
    startPrivKey = crypto.randomBytes(32);
    while (!ecc.isPrivate(startPrivKey)) {
      startPrivKey = crypto.randomBytes(32);
    }
    currentPubKey = Buffer.from(ecc.pointFromScalar(startPrivKey, true));
    offset = 0;
    continue;
  }
  currentPubKey = Buffer.from(next);

  // Progress report every 3 seconds
  const now = Date.now();
  if (now - lastReport >= 3000) {
    parentPort.postMessage({ type: 'progress', attempts });
    lastReport = now;
    attempts = 0;
  }
}
