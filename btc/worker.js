const { parentPort, workerData } = require('worker_threads');
const crypto = require('crypto');
const ecc = require('tiny-secp256k1');

const { prefix, suffix, addrKey, startKey, workerId } = workerData;
const isBech32 = addrKey === 'nativeSegwit' || addrKey === 'taproot';

// ── Base58 constants ──
const BASE58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

// ── Generator point G (for incremental keygen) ──
const ONE = Buffer.alloc(32);
ONE[31] = 1;
const G_POINT = Buffer.from(ecc.pointFromScalar(ONE, true));

// ── Bech32 constants ──
const BECH32_CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
const BECH32_GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];

// ── Hash utilities ──
function sha256(data) {
  return crypto.createHash('sha256').update(data).digest();
}

function hash160(data) {
  return crypto.createHash('ripemd160').update(sha256(data)).digest();
}

// ── Pre-compute suffix target for base58 modular check (suffix-only, no prefix) ──
let MOD, suffixTarget;
const useFastSuffix = !isBech32 && suffix && !prefix;
if (useFastSuffix) {
  MOD = Math.pow(58, suffix.length);
  suffixTarget = 0;
  for (const ch of suffix) {
    suffixTarget = suffixTarget * 58 + BASE58.indexOf(ch);
  }
}

// ── Prefix constants (version prefixes to skip) ──
const VERSION_PREFIX = {
  legacy: '1',
  nested: '3',
  nativeSegwit: 'bc1q',
  taproot: 'bc1p',
};
const versionPrefix = VERSION_PREFIX[addrKey];

// ── Pre-allocated buffers for base58 address computation ──
const redeemBuf = Buffer.allocUnsafe(22);
redeemBuf[0] = 0x00;
redeemBuf[1] = 0x14;
const payloadBuf = Buffer.allocUnsafe(21);
const fullBuf = Buffer.allocUnsafe(25);

function checkBase58Suffix(pubkey) {
  const h = hash160(pubkey);

  if (addrKey === 'legacy') {
    payloadBuf[0] = 0x00;
    h.copy(payloadBuf, 1);
  } else {
    h.copy(redeemBuf, 2);
    const sh = hash160(redeemBuf);
    payloadBuf[0] = 0x05;
    sh.copy(payloadBuf, 1);
  }

  const cs = sha256(sha256(payloadBuf));
  payloadBuf.copy(fullBuf);
  cs.copy(fullBuf, 21, 0, 4);

  let r = 0;
  for (let i = 0; i < 25; i++) {
    r = (r * 256 + fullBuf[i]) % MOD;
  }
  return r === suffixTarget;
}

// ── Full base58 encoding ──
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

function base58Address(pubkey, type) {
  const h = hash160(pubkey);
  let payload;
  if (type === 'legacy') {
    payload = Buffer.concat([Buffer.from([0x00]), h]);
  } else {
    const redeem = Buffer.concat([Buffer.from([0x00, 0x14]), h]);
    const sh = hash160(redeem);
    payload = Buffer.concat([Buffer.from([0x05]), sh]);
  }
  const cs = sha256(sha256(payload));
  return base58Encode(Buffer.concat([payload, cs.subarray(0, 4)]));
}

// ── Bech32 encoding ──
function bech32Polymod(values) {
  let chk = 1;
  for (let i = 0; i < values.length; i++) {
    const b = chk >> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ values[i];
    for (let j = 0; j < 5; j++) {
      chk ^= (b >> j) & 1 ? BECH32_GEN[j] : 0;
    }
  }
  return chk;
}

function bech32Encode(witnessVersion, program, spec) {
  const data5 = [witnessVersion];
  let acc = 0, bits = 0;
  for (let i = 0; i < program.length; i++) {
    acc = (acc << 8) | program[i];
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      data5.push((acc >> bits) & 31);
    }
  }
  if (bits > 0) data5.push((acc << (5 - bits)) & 31);

  const hrpExp = [0, 0, 3, 3, 0, 2, 3];
  const enc = spec === 'bech32m' ? 0x2bc830a3 : 1;
  const values = [...hrpExp, ...data5, 0, 0, 0, 0, 0, 0];
  const polymod = bech32Polymod(values) ^ enc;
  const checksum = [];
  for (let i = 0; i < 6; i++) {
    checksum.push((polymod >> (5 * (5 - i))) & 31);
  }

  const combined = [...data5, ...checksum];
  let result = 'bc1';
  for (let i = 0; i < combined.length; i++) {
    result += BECH32_CHARSET[combined[i]];
  }
  return result;
}

// ── Taproot tagged hash ──
const TAP_TWEAK_TAG = sha256(Buffer.from('TapTweak'));
const TAP_TWEAK_PREFIX = Buffer.concat([TAP_TWEAK_TAG, TAP_TWEAK_TAG]);

function tapTweakHash(xOnlyPubkey) {
  return sha256(Buffer.concat([TAP_TWEAK_PREFIX, xOnlyPubkey]));
}

function getBech32Address(pubkey) {
  if (addrKey === 'nativeSegwit') {
    const h = hash160(pubkey);
    return bech32Encode(0, h, 'bech32');
  } else {
    const xOnly = pubkey.subarray(1, 33);
    const tweak = tapTweakHash(xOnly);
    const result = ecc.xOnlyPointAddTweak(xOnly, tweak);
    if (!result) return '';
    return bech32Encode(1, Buffer.from(result.xOnlyPubkey), 'bech32m');
  }
}

// ── WIF encoding ──
function toWIF(privKeyBytes) {
  const payload = Buffer.concat([Buffer.from([0x80]), privKeyBytes, Buffer.from([0x01])]);
  const cs = sha256(sha256(payload));
  return base58Encode(Buffer.concat([payload, cs.subarray(0, 4)]));
}

// ── Get all addresses for a keypair ──
function getAllAddresses(pubkey) {
  const xOnly = pubkey.subarray(1, 33);
  const tweak = tapTweakHash(xOnly);
  const tweaked = ecc.xOnlyPointAddTweak(xOnly, tweak);

  return {
    legacy: base58Address(pubkey, 'legacy'),
    nested: base58Address(pubkey, 'nested'),
    nativeSegwit: bech32Encode(0, hash160(pubkey), 'bech32'),
    taproot: tweaked ? bech32Encode(1, Buffer.from(tweaked.xOnlyPubkey), 'bech32m') : 'N/A',
  };
}

// ── Pre-compute patterns ──
const prefixPattern = prefix ? (isBech32 ? prefix.toLowerCase() : prefix) : null;
const suffixPattern = suffix ? (isBech32 ? suffix.toLowerCase() : suffix) : null;

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
  let matched = false;

  if (useFastSuffix) {
    // Optimized path: suffix-only with modular arithmetic
    matched = checkBase58Suffix(currentPubKey);
  } else {
    // General path: full address generation, check prefix and/or suffix
    let addr;
    if (!isBech32) {
      addr = base58Address(currentPubKey, addrKey);
    } else {
      addr = getBech32Address(currentPubKey);
    }

    const afterVersionPrefix = addr.substring(versionPrefix.length);

    const prefixOk = !prefixPattern || (isBech32
      ? afterVersionPrefix.startsWith(prefixPattern)
      : afterVersionPrefix.startsWith(prefixPattern));
    const suffixOk = !suffixPattern || addr.endsWith(suffixPattern);

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

    let address;
    if (!isBech32) {
      address = base58Address(pubkey, addrKey);
    } else {
      address = getBech32Address(pubkey);
    }

    const wif = toWIF(privKey);
    const addresses = getAllAddresses(pubkey);

    parentPort.postMessage({
      type: 'found',
      address,
      wif,
      pubkey: Buffer.from(pubkey).toString('hex'),
      attempts,
      addresses,
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
