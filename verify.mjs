/**
 * x402-doge reference verifier: `exact` scheme on Dogecoin, `rawTransaction` method.
 *
 * Dependency-free (Node >= 18: node:crypto, BigInt). Facilitator-side only: it never
 * holds keys and never signs. Normative rules are in ./spec.md; where this file and
 * the spec disagree, the spec wins and this file has a bug.
 *
 * Layers:
 *   checkRequirements(req)                      requirements shape (§4)
 *   checkStatic({paymentPayload, paymentRequirements, now})
 *                                               everything provable from the bytes (§8.2)
 *   checkWithPrevouts(st, prevouts, ctx)        fees, inputs, scripts (§8.3)
 *   verifyWithCore(rpc, body, opts)             /verify against Dogecoin Core 1.14.x (§8)
 *   settleWithCore(rpc, body, opts)             /settle against Dogecoin Core 1.14.x (§9)
 *
 * `rpc(method, params)` is injected: it returns the JSON-RPC `result` or throws an
 * Error carrying `.code` (the JSON-RPC error code) and `.message`.
 */
import { createHash, createPublicKey, verify as ecVerify } from 'node:crypto';

export const X402_VERSION = 2;
export const SCHEME = 'exact';
export const ASSET = 'DOGE';
export const METHOD = 'rawTransaction';

/** CAIP-2 ids (BIP122: first 32 hex chars of the genesis block hash). */
export const NETWORKS = Object.freeze({
  'bip122:1a91e3dace36e2be3bf030a65679fe82': Object.freeze({ name: 'dogecoin', p2pkh: 30, p2sh: 22, coinbaseMaturity: 240 }),
  'bip122:bb0a78264637406b6360aad926284d54': Object.freeze({ name: 'dogecoin-testnet', p2pkh: 113, p2sh: 196, coinbaseMaturity: 240 }),
});

/** Dogecoin Core 1.14.9 defaults (src/policy/policy.h, src/validation.h, doc/fee-recommendation.md). */
export const POLICY = Object.freeze({
  KOINU_PER_DOGE: 100_000_000n,
  SOFT_DUST: 1_000_000n, // 0.01 DOGE: DEFAULT_DUST_LIMIT; each output below it adds 0.01 DOGE to the relay fee
  HARD_DUST: 100_000n, // 0.001 DOGE: DEFAULT_HARD_DUST_LIMIT; below it the tx is non-standard
  RECOMMENDED_FEE_PER_KB: 1_000_000n, // 0.01 DOGE/kB: RECOMMENDED_MIN_TX_FEE, miner default inclusion
  MIN_RELAY_FEE_PER_KB: 100_000n, // 0.001 DOGE/kB: DEFAULT_MIN_RELAY_TX_FEE
  MAX_FEE: 10_000_000_000n, // 100 DOGE: DEFAULT_TRANSACTION_MAXFEE (sendrawtransaction "absurdly-high-fee")
  MAX_MONEY: 1_000_000_000_000_000_000n, // 10,000,000,000 DOGE per output (MAX_MONEY)
  MAX_TX_BYTES: 100_000, // MAX_STANDARD_TX_WEIGHT / 4 (no witness on Dogecoin)
  MAX_INPUTS: 100, // scheme budget, not a Core rule
  MAX_STANDARD_VERSION: 2,
  MAX_CONFIRMATIONS: 60, // scheme cap on extra.minConfirmations
  CLOCK_SKEW_SECONDS: 30,
});

/** "x402" + binding version 0x01. The OP_RETURN data is this 5-byte tag + the 16-byte nonce. */
export const BINDING_TAG = Uint8Array.from([0x78, 0x34, 0x30, 0x32, 0x01]);

const SEQ_FINAL = 0xffffffff;
const SEQ_NO_RBF_MIN = 0xfffffffe; // BIP125: any input below this signals replaceability
const LOCKTIME_THRESHOLD = 500_000_000;
const SIGHASH_ALL = 0x01;
const SECP256K1_N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const SECP256K1_HALF_N = SECP256K1_N >> 1n;

// ---------------------------------------------------------------------------
// bytes

export function hexToBytes(hex) {
  if (typeof hex !== 'string' || hex.length % 2 !== 0 || !/^[0-9a-f]*$/.test(hex)) throw new Error('hex: expected lowercase even-length hex');
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i += 1) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

export function bytesToHex(bytes) {
  let s = '';
  for (const b of bytes) s += b.toString(16).padStart(2, '0');
  return s;
}

function concat(...parts) {
  const n = parts.reduce((a, p) => a + p.length, 0);
  const out = new Uint8Array(n);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

function equalBytes(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i += 1) if (a[i] !== b[i]) return false;
  return true;
}

export function sha256(b) {
  return new Uint8Array(createHash('sha256').update(b).digest());
}

export function sha256d(b) {
  return sha256(sha256(b));
}

export function hash160(b) {
  let h;
  try {
    h = createHash('ripemd160');
  } catch {
    throw new Error('hash160: this Node/OpenSSL build has no ripemd160');
  }
  return new Uint8Array(h.update(sha256(b)).digest());
}

function u32le(n) {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n >>> 0, true);
  return b;
}

function i32le(n) {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setInt32(0, n | 0, true);
  return b;
}

function u64le(v) {
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigUint64(0, BigInt.asUintN(64, v), true);
  return b;
}

function varint(n) {
  if (n < 0xfd) return Uint8Array.of(n);
  if (n <= 0xffff) return Uint8Array.of(0xfd, n & 0xff, n >>> 8);
  return concat(Uint8Array.of(0xfe), u32le(n));
}

function reversedHex(bytes) {
  return bytesToHex(Uint8Array.from(bytes).reverse());
}

// ---------------------------------------------------------------------------
// transactions (legacy serialization; Dogecoin has no active segwit)

/** Decode a raw Dogecoin transaction. Throws on any malformed byte. */
export function decodeTransaction(hex) {
  const raw = hexToBytes(hex);
  const dv = new DataView(raw.buffer, raw.byteOffset, raw.byteLength);
  let o = 0;
  const need = (n) => {
    if (o + n > raw.length) throw new Error('tx: truncated');
  };
  const readVarint = () => {
    need(1);
    const first = raw[o];
    o += 1;
    if (first < 0xfd) return first;
    if (first === 0xfd) {
      need(2);
      const v = dv.getUint16(o, true);
      o += 2;
      if (v < 0xfd) throw new Error('tx: non-canonical varint');
      return v;
    }
    if (first === 0xfe) {
      need(4);
      const v = dv.getUint32(o, true);
      o += 4;
      if (v <= 0xffff) throw new Error('tx: non-canonical varint');
      return v;
    }
    throw new Error('tx: varint too large');
  };
  const readBytes = (n) => {
    need(n);
    const b = raw.slice(o, o + n);
    o += n;
    return b;
  };
  need(4);
  const version = dv.getInt32(o, true);
  o += 4;
  const nIn = readVarint();
  if (nIn === 0) throw new Error('tx: no inputs (or a segwit marker, which Dogecoin does not use)');
  const vin = [];
  for (let i = 0; i < nIn; i += 1) {
    const prevHash = readBytes(32);
    need(4);
    const vout = dv.getUint32(o, true);
    o += 4;
    const scriptSig = readBytes(readVarint());
    need(4);
    const sequence = dv.getUint32(o, true);
    o += 4;
    vin.push({ txid: reversedHex(prevHash), prevHash, vout, scriptSig, sequence });
  }
  const nOut = readVarint();
  if (nOut === 0) throw new Error('tx: no outputs');
  const vout = [];
  for (let i = 0; i < nOut; i += 1) {
    need(8);
    const value = dv.getBigInt64(o, true);
    o += 8;
    if (value < 0n || value > POLICY.MAX_MONEY) throw new Error('tx: output value out of range');
    vout.push({ value, script: readBytes(readVarint()) });
  }
  need(4);
  const locktime = dv.getUint32(o, true);
  o += 4;
  if (o !== raw.length) throw new Error('tx: trailing bytes');
  return { version, vin, vout, locktime, size: raw.length, raw, txid: reversedHex(sha256d(raw)) };
}

function serializeForSighash(tx, inputIndex, scriptCode, hashType) {
  const parts = [i32le(tx.version), varint(tx.vin.length)];
  tx.vin.forEach((input, j) => {
    const script = j === inputIndex ? scriptCode : new Uint8Array(0);
    parts.push(input.prevHash, u32le(input.vout), varint(script.length), script, u32le(input.sequence));
  });
  parts.push(varint(tx.vout.length));
  for (const out of tx.vout) parts.push(u64le(out.value), varint(out.script.length), out.script);
  parts.push(u32le(tx.locktime), u32le(hashType));
  return concat(...parts);
}

/** Legacy SIGHASH_ALL digest for input `i` (scriptCode = the P2PKH prevout script). */
export function sighashAll(tx, i, scriptCode) {
  return sha256d(serializeForSighash(tx, i, scriptCode, SIGHASH_ALL));
}

// ---------------------------------------------------------------------------
// scripts and addresses

const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

function base58Decode(s) {
  if (typeof s !== 'string' || !s.length) throw new Error('base58: empty');
  let n = 0n;
  for (const ch of s) {
    const d = B58.indexOf(ch);
    if (d < 0) throw new Error('base58: bad character');
    n = n * 58n + BigInt(d);
  }
  const bytes = [];
  while (n > 0n) {
    bytes.unshift(Number(n & 0xffn));
    n >>= 8n;
  }
  for (const ch of s) {
    if (ch !== '1') break;
    bytes.unshift(0);
  }
  return Uint8Array.from(bytes);
}

function base58Encode(bytes) {
  let n = 0n;
  for (const b of bytes) n = (n << 8n) | BigInt(b);
  let s = '';
  while (n > 0n) {
    s = B58[Number(n % 58n)] + s;
    n /= 58n;
  }
  for (const b of bytes) {
    if (b !== 0) break;
    s = `1${s}`;
  }
  return s;
}

function base58CheckDecode(addr) {
  const b = base58Decode(addr);
  if (b.length !== 25) throw new Error('address: wrong length');
  const body = b.slice(0, 21);
  if (!equalBytes(sha256d(body).slice(0, 4), b.slice(21))) throw new Error('address: bad checksum');
  return { version: body[0], hash: body.slice(1) };
}

function p2pkhScript(h) {
  return concat(Uint8Array.of(0x76, 0xa9, 0x14), h, Uint8Array.of(0x88, 0xac));
}

function p2shScript(h) {
  return concat(Uint8Array.of(0xa9, 0x14), h, Uint8Array.of(0x87));
}

function isP2pkh(s) {
  return s.length === 25 && s[0] === 0x76 && s[1] === 0xa9 && s[2] === 0x14 && s[23] === 0x88 && s[24] === 0xac;
}

function isP2sh(s) {
  return s.length === 23 && s[0] === 0xa9 && s[1] === 0x14 && s[22] === 0x87;
}

/** scriptPubKey for a Dogecoin P2PKH or P2SH address on `network` (CAIP-2). */
export function addressToScript(address, network) {
  const net = NETWORKS[network];
  if (!net) throw new Error('address: unknown network');
  const { version, hash } = base58CheckDecode(address);
  if (version === net.p2pkh) return p2pkhScript(hash);
  if (version === net.p2sh) return p2shScript(hash);
  throw new Error('address: not a P2PKH or P2SH address on this network');
}

export function scriptToAddress(script, network) {
  const net = NETWORKS[network];
  if (!net) return null;
  let version;
  let hash;
  if (isP2pkh(script)) {
    version = net.p2pkh;
    hash = script.slice(3, 23);
  } else if (isP2sh(script)) {
    version = net.p2sh;
    hash = script.slice(2, 22);
  } else return null;
  const body = concat(Uint8Array.of(version), hash);
  return base58Encode(concat(body, sha256d(body).slice(0, 4)));
}

/** The one OP_RETURN output a payment carries: OP_RETURN PUSH21 "x402" 0x01 <nonce16>. */
export function bindingScript(nonceHex) {
  const nonce = hexToBytes(nonceHex);
  if (nonce.length !== 16) throw new Error('nonce: expected 16 bytes');
  return concat(Uint8Array.of(0x6a, 0x15), BINDING_TAG, nonce);
}

function isOpReturn(s) {
  return s.length > 0 && s[0] === 0x6a;
}

/** Parse a P2PKH scriptSig: exactly <sig+hashtype> <pubkey>, minimal direct pushes. */
function parseP2pkhScriptSig(s) {
  if (s.length < 2) return null;
  const sigLen = s[0];
  if (sigLen < 9 || sigLen > 73 || 1 + sigLen >= s.length) return null;
  const sig = s.slice(1, 1 + sigLen);
  const pkLen = s[1 + sigLen];
  if (pkLen !== 33 && pkLen !== 65) return null;
  if (2 + sigLen + pkLen !== s.length) return null;
  const pubkey = s.slice(2 + sigLen);
  return { sig, pubkey };
}

// BIP66 strict DER (port of Bitcoin Core IsValidSignatureEncoding; `sig` includes the hashtype byte).
function isValidSignatureEncoding(sig) {
  if (sig.length < 9 || sig.length > 73) return false;
  if (sig[0] !== 0x30) return false;
  if (sig[1] !== sig.length - 3) return false;
  const lenR = sig[3];
  if (5 + lenR >= sig.length) return false;
  const lenS = sig[5 + lenR];
  if (lenR + lenS + 7 !== sig.length) return false;
  if (sig[2] !== 0x02) return false;
  if (lenR === 0) return false;
  if (sig[4] & 0x80) return false;
  if (lenR > 1 && sig[4] === 0x00 && !(sig[5] & 0x80)) return false;
  if (sig[lenR + 4] !== 0x02) return false;
  if (lenS === 0) return false;
  if (sig[lenR + 6] & 0x80) return false;
  if (lenS > 1 && sig[lenR + 6] === 0x00 && !(sig[lenR + 7] & 0x80)) return false;
  return true;
}

function derS(sig) {
  const lenR = sig[3];
  const lenS = sig[5 + lenR];
  let s = 0n;
  for (const b of sig.slice(6 + lenR, 6 + lenR + lenS)) s = (s << 8n) | BigInt(b);
  return s;
}

const SPKI_COMPRESSED = hexToBytes('3036301006072a8648ce3d020106052b8104000a032200');
const SPKI_UNCOMPRESSED = hexToBytes('3056301006072a8648ce3d020106052b8104000a034200');

function pubkeyOk(pk) {
  return (pk.length === 33 && (pk[0] === 0x02 || pk[0] === 0x03)) || (pk.length === 65 && pk[0] === 0x04);
}

/**
 * Check input `i` spends a P2PKH prevout with a valid, low-S, strict-DER SIGHASH_ALL
 * signature. Returns null if fine, otherwise a reason code.
 */
export function checkP2pkhInput(tx, i, prevScript) {
  if (!isP2pkh(prevScript)) return 'invalid_exact_dogecoin_unsupported_input';
  const parsed = parseP2pkhScriptSig(tx.vin[i].scriptSig);
  if (!parsed) return 'invalid_exact_dogecoin_script_invalid';
  const { sig, pubkey } = parsed;
  if (!pubkeyOk(pubkey)) return 'invalid_exact_dogecoin_script_invalid';
  if (!equalBytes(hash160(pubkey), prevScript.slice(3, 23))) return 'invalid_exact_dogecoin_script_invalid';
  if (!isValidSignatureEncoding(sig)) return 'invalid_exact_dogecoin_script_invalid';
  if (sig[sig.length - 1] !== SIGHASH_ALL) return 'invalid_exact_dogecoin_sighash_type';
  const der = sig.slice(0, sig.length - 1);
  if (derS(sig) > SECP256K1_HALF_N) return 'invalid_exact_dogecoin_script_invalid';
  let ok = false;
  try {
    const key = createPublicKey({ key: Buffer.from(concat(pubkey.length === 33 ? SPKI_COMPRESSED : SPKI_UNCOMPRESSED, pubkey)), format: 'der', type: 'spki' });
    // ECDSA over the sighash z = sha256d(preimage): Node hashes its input once with
    // sha256, so hand it sha256(preimage) and it verifies over sha256(sha256(preimage)).
    ok = ecVerify('sha256', Buffer.from(sha256(serializeForSighash(tx, i, prevScript, SIGHASH_ALL))), key, Buffer.from(der));
  } catch {
    ok = false;
  }
  return ok ? null : 'invalid_exact_dogecoin_script_invalid';
}

// ---------------------------------------------------------------------------
// requirements (§4)

const KOINU_RE = /^(0|[1-9][0-9]{0,18})$/;
const NONCE_RE = /^[0-9a-f]{32}$/;
const UNIX_RE = /^[1-9][0-9]{0,11}$/;

/** Normalize `extra` with defaults. Throws on an invalid value. */
export function normalizeExtra(extra = {}) {
  if (extra === null || typeof extra !== 'object' || Array.isArray(extra)) throw new Error('extra must be an object');
  const method = extra.assetTransferMethod ?? METHOD;
  if (method !== METHOD) throw new Error('unsupported assetTransferMethod');
  const minConfirmations = extra.minConfirmations ?? 0;
  if (!Number.isInteger(minConfirmations) || minConfirmations < 0 || minConfirmations > POLICY.MAX_CONFIRMATIONS) throw new Error('minConfirmations out of range');
  const flow = extra.paymentFlow ?? (minConfirmations > 0 ? null : 'authorization');
  if (minConfirmations > 0 && flow !== 'upfront') throw new Error('minConfirmations >= 1 requires paymentFlow "upfront"');
  if (flow !== 'authorization' && flow !== 'upfront') throw new Error('unsupported paymentFlow');
  if (typeof extra.nonce !== 'string' || !NONCE_RE.test(extra.nonce)) throw new Error('nonce must be 32 lowercase hex chars');
  if (typeof extra.validBefore !== 'string' || !UNIX_RE.test(extra.validBefore)) throw new Error('validBefore must be a unix-seconds string');
  let minFeePerKb = POLICY.RECOMMENDED_FEE_PER_KB;
  if (extra.minFeePerKb !== undefined) {
    if (typeof extra.minFeePerKb !== 'string' || !KOINU_RE.test(extra.minFeePerKb)) throw new Error('minFeePerKb must be a koinu string');
    minFeePerKb = BigInt(extra.minFeePerKb);
    if (minFeePerKb < POLICY.MIN_RELAY_FEE_PER_KB) throw new Error('minFeePerKb below the relay minimum');
  }
  return { method, flow, minConfirmations, nonce: extra.nonce, validBefore: Number(extra.validBefore), minFeePerKb };
}

/** Returns { ok: true, extra } or { ok: false, reason }. */
export function checkRequirements(req) {
  if (!req || typeof req !== 'object') return { ok: false, reason: 'invalid_payment_requirements' };
  if (req.scheme !== SCHEME) return { ok: false, reason: 'invalid_scheme' };
  if (!NETWORKS[req.network]) return { ok: false, reason: 'invalid_network' };
  if (req.asset !== ASSET) return { ok: false, reason: 'invalid_exact_dogecoin_asset_mismatch' };
  if (typeof req.amount !== 'string' || !KOINU_RE.test(req.amount)) return { ok: false, reason: 'invalid_payment_requirements' };
  const amount = BigInt(req.amount);
  if (amount < POLICY.SOFT_DUST || amount > POLICY.MAX_MONEY) return { ok: false, reason: 'invalid_payment_requirements' };
  if (!Number.isInteger(req.maxTimeoutSeconds) || req.maxTimeoutSeconds < 1) return { ok: false, reason: 'invalid_payment_requirements' };
  try {
    addressToScript(req.payTo, req.network);
  } catch {
    return { ok: false, reason: 'invalid_payment_requirements' };
  }
  try {
    return { ok: true, amount, extra: normalizeExtra(req.extra) };
  } catch {
    return { ok: false, reason: 'invalid_payment_requirements' };
  }
}

/** Canonical JSON (sorted keys) for the `accepted` == `paymentRequirements` comparison. */
export function canonicalJson(v) {
  if (v === null || typeof v !== 'object') return JSON.stringify(v);
  if (Array.isArray(v)) return `[${v.map(canonicalJson).join(',')}]`;
  return `{${Object.keys(v)
    .filter((k) => v[k] !== undefined)
    .sort()
    .map((k) => `${JSON.stringify(k)}:${canonicalJson(v[k])}`)
    .join(',')}}`;
}

// ---------------------------------------------------------------------------
// static checks (§8.2): everything provable from the payload bytes alone

/**
 * Returns { isValid: false, invalidReason } or
 * { isValid: true, tx, txid, amount, extra, payIndex, network }.
 * `now` is unix seconds. `allowExpired` is only for resuming a settlement already broadcast.
 */
export function checkStatic({ paymentPayload, paymentRequirements, now, allowExpired = false }) {
  const bad = (invalidReason) => ({ isValid: false, invalidReason });
  if (!paymentPayload || paymentPayload.x402Version !== X402_VERSION) return bad('invalid_x402_version');
  const req = paymentRequirements;
  const r = checkRequirements(req);
  if (!r.ok) return bad(r.reason);
  if (canonicalJson(paymentPayload.accepted) !== canonicalJson(req)) return bad('invalid_exact_dogecoin_requirements_mismatch');
  const { amount, extra } = r;
  if (!allowExpired) {
    if (now >= extra.validBefore) return bad('invalid_exact_dogecoin_expired');
    if (extra.validBefore > now + req.maxTimeoutSeconds + POLICY.CLOCK_SKEW_SECONDS) return bad('invalid_payment_requirements');
  }
  const hex = paymentPayload.payload?.transaction;
  if (typeof hex !== 'string' || hex.length > POLICY.MAX_TX_BYTES * 2) return bad('invalid_exact_dogecoin_transaction_malformed');
  let tx;
  try {
    tx = decodeTransaction(hex);
  } catch {
    return bad('invalid_exact_dogecoin_transaction_malformed');
  }
  if (tx.size > POLICY.MAX_TX_BYTES || tx.vin.length > POLICY.MAX_INPUTS) return bad('invalid_exact_dogecoin_transaction_too_large');
  if (tx.version < 1 || tx.version > POLICY.MAX_STANDARD_VERSION) return bad('invalid_exact_dogecoin_nonstandard');

  // Inputs: distinct outpoints, signed, no BIP125 signal when accepting 0-conf.
  const seen = new Set();
  for (const input of tx.vin) {
    const key = `${input.txid}:${input.vout}`;
    if (seen.has(key)) return bad('invalid_exact_dogecoin_transaction_malformed');
    seen.add(key);
    if (input.scriptSig.length === 0) return bad('invalid_exact_dogecoin_script_invalid');
    if (extra.minConfirmations === 0 && input.sequence < SEQ_NO_RBF_MIN) return bad('invalid_exact_dogecoin_rbf_signaled');
  }
  // Locktime: final now. A time lock is refused unless every sequence is final.
  const allFinal = tx.vin.every((i) => i.sequence === SEQ_FINAL);
  if (tx.locktime !== 0 && !allFinal && tx.locktime >= LOCKTIME_THRESHOLD) return bad('invalid_exact_dogecoin_locktime');

  // Outputs: exactly one to payTo for exactly `amount`, exactly one binding OP_RETURN.
  const payScript = addressToScript(req.payTo, req.network);
  const binding = bindingScript(extra.nonce);
  let payIndex = -1;
  let bindingCount = 0;
  for (let k = 0; k < tx.vout.length; k += 1) {
    const out = tx.vout[k];
    if (isOpReturn(out.script)) {
      if (!equalBytes(out.script, binding) || out.value !== 0n) return bad('invalid_exact_dogecoin_binding_mismatch');
      bindingCount += 1;
      continue;
    }
    if (equalBytes(out.script, payScript)) {
      if (payIndex !== -1) return bad('invalid_exact_dogecoin_recipient_mismatch');
      payIndex = k;
      continue;
    }
    if (out.value < POLICY.HARD_DUST) return bad('invalid_exact_dogecoin_nonstandard');
    if (!isP2pkh(out.script) && !isP2sh(out.script)) return bad('invalid_exact_dogecoin_nonstandard');
  }
  if (bindingCount !== 1) return bad('invalid_exact_dogecoin_binding_missing');
  if (payIndex === -1) return bad('invalid_exact_dogecoin_recipient_mismatch');
  if (tx.vout[payIndex].value !== amount) return bad('invalid_exact_dogecoin_amount_mismatch');
  return { isValid: true, tx, txid: tx.txid, amount, extra, payIndex, network: req.network };
}

// ---------------------------------------------------------------------------
// prevout checks (§8.3)

/**
 * `prevouts[i]` = { value: bigint koinu, script: Uint8Array, confirmations: number, coinbase: boolean }
 * for tx.vin[i], read from the facilitator's own node (unspent, mempool included).
 * `ctx` = { tipHeight, verifyScripts = true }.
 */
export function checkWithPrevouts(st, prevouts, ctx = {}) {
  const bad = (invalidReason, payer) => ({ isValid: false, invalidReason, ...(payer ? { payer } : {}) });
  const { tx, extra, network } = st;
  const net = NETWORKS[network];
  if (!Array.isArray(prevouts) || prevouts.length !== tx.vin.length) return bad('unexpected_verify_error');
  const payer = scriptToAddress(prevouts[0]?.script ?? new Uint8Array(0), network) ?? undefined;
  let inSum = 0n;
  for (let i = 0; i < tx.vin.length; i += 1) {
    const p = prevouts[i];
    if (!p) return bad('invalid_exact_dogecoin_input_missing', payer);
    if (!isP2pkh(p.script)) return bad('invalid_exact_dogecoin_unsupported_input', payer);
    if (extra.minConfirmations === 0 && !(p.confirmations >= 1)) return bad('invalid_exact_dogecoin_input_unconfirmed', payer);
    if (p.coinbase && !(p.confirmations >= net.coinbaseMaturity)) return bad('invalid_exact_dogecoin_input_immature', payer);
    inSum += p.value;
  }
  if (ctx.tipHeight != null && tx.locktime !== 0 && tx.locktime < LOCKTIME_THRESHOLD && !tx.vin.every((i) => i.sequence === SEQ_FINAL)) {
    // Height lock: final once nLockTime < the height of the next block.
    if (tx.locktime > ctx.tipHeight) return bad('invalid_exact_dogecoin_locktime', payer);
  }
  const outSum = tx.vout.reduce((a, o) => a + o.value, 0n);
  if (inSum < outSum) return bad('insufficient_funds', payer);
  const fee = inSum - outSum;
  const dustOutputs = tx.vout.filter((o) => !isOpReturn(o.script) && o.value < POLICY.SOFT_DUST).length;
  const sizeFee = (BigInt(tx.size) * extra.minFeePerKb + 999n) / 1000n;
  const required = sizeFee + BigInt(dustOutputs) * POLICY.SOFT_DUST;
  if (fee < required) return bad('invalid_exact_dogecoin_fee_too_low', payer);
  if (fee > POLICY.MAX_FEE) return bad('invalid_exact_dogecoin_fee_too_high', payer);
  if (ctx.verifyScripts !== false) {
    for (let i = 0; i < tx.vin.length; i += 1) {
      const reason = checkP2pkhInput(tx, i, prevouts[i].script);
      if (reason) return bad(reason, payer);
    }
  }
  return { isValid: true, payer, fee };
}

// ---------------------------------------------------------------------------
// Dogecoin Core 1.14.x glue

/** Exact koinu from an RPC amount. Strings are exact; numbers only below 1,000,000 DOGE. */
export function koinuFromRpc(v) {
  if (typeof v === 'string') {
    const m = /^(\d+)(?:\.(\d{1,8}))?$/.exec(v);
    if (!m) throw new Error('amount: bad decimal');
    return BigInt(m[1]) * POLICY.KOINU_PER_DOGE + BigInt((m[2] ?? '').padEnd(8, '0'));
  }
  if (typeof v !== 'number' || !Number.isFinite(v) || v < 0) throw new Error('amount: bad number');
  if (v >= 1_000_000) throw new Error('amount: too large to read exactly from a JSON number');
  return koinuFromRpc(v.toFixed(8));
}

/**
 * Prevout for one input: unspent (mempool included) via gettxout; exact value and
 * script from the previous transaction's bytes when getrawtransaction can serve it.
 */
export async function readPrevout(rpc, input) {
  const utxo = await rpc('gettxout', [input.txid, input.vout, true]);
  if (!utxo) return null; // spent (in chain or mempool) or never existed
  let value;
  let script = hexToBytes(String(utxo.scriptPubKey?.hex ?? ''));
  try {
    const prevHex = await rpc('getrawtransaction', [input.txid, 0]);
    const prev = decodeTransaction(prevHex);
    const out = prev.vout[input.vout];
    if (!out) return null;
    if (!equalBytes(out.script, script)) throw new Error('prevout: script mismatch between RPCs');
    value = out.value;
    script = out.script;
  } catch (e) {
    if (e instanceof Error && /script mismatch/.test(e.message)) throw e;
    value = koinuFromRpc(utxo.value); // no -txindex: fall back to the JSON amount
  }
  return { value, script, confirmations: Number(utxo.confirmations ?? 0), coinbase: Boolean(utxo.coinbase) };
}

/**
 * POST /verify. Read-only: gettxout, getrawtransaction, getblockcount and (optionally)
 * signrawtransaction with an empty key list, which only checks the existing scripts.
 * opts = { now?: unix seconds, coreScriptCheck?: boolean (default true) }
 */
export async function verifyWithCore(rpc, body, opts = {}) {
  const now = opts.now ?? Math.floor(Date.now() / 1000);
  try {
    if (body?.x402Version !== X402_VERSION) return { isValid: false, invalidReason: 'invalid_x402_version' };
    const st = checkStatic({ paymentPayload: body.paymentPayload, paymentRequirements: body.paymentRequirements, now, allowExpired: opts.allowExpired });
    if (!st.isValid) return st;
    const prevouts = [];
    for (const input of st.tx.vin) {
      const p = await readPrevout(rpc, input);
      if (!p) return { isValid: false, invalidReason: 'invalid_exact_dogecoin_input_missing' };
      prevouts.push(p);
    }
    const tipHeight = await rpc('getblockcount', []);
    const res = checkWithPrevouts(st, prevouts, { tipHeight, verifyScripts: true });
    if (!res.isValid) return res;
    if (opts.coreScriptCheck !== false) {
      // Core 1.14 has no testmempoolaccept. signrawtransaction with privkeys = []
      // signs nothing and reports script failures under STANDARD_SCRIPT_VERIFY_FLAGS.
      const chk = await rpc('signrawtransaction', [body.paymentPayload.payload.transaction, [], []]);
      if (!chk || chk.complete !== true || chk.hex !== body.paymentPayload.payload.transaction) {
        return { isValid: false, invalidReason: 'invalid_exact_dogecoin_script_invalid', payer: res.payer };
      }
    }
    return { isValid: true, payer: res.payer };
  } catch {
    return { isValid: false, invalidReason: 'unexpected_verify_error' };
  }
}

// ---------------------------------------------------------------------------
// settlement (§9)

/** In-process claim store. Multi-instance facilitators need a shared, atomic one. */
export function memoryClaimStore() {
  const m = new Map();
  const live = (k, now) => {
    const e = m.get(k);
    if (e && e.expiresAt <= now) {
      m.delete(k);
      return undefined;
    }
    return e;
  };
  return {
    async get(k, now = Math.floor(Date.now() / 1000)) {
      return live(k, now)?.value;
    },
    /** Atomic insert-if-absent. */
    async claim(k, value, expiresAt, now = Math.floor(Date.now() / 1000)) {
      if (live(k, now)) return false;
      m.set(k, { value, expiresAt });
      return true;
    },
    async set(k, value, expiresAt) {
      m.set(k, { value, expiresAt });
    },
    async release(k) {
      m.delete(k);
    },
  };
}

export function nonceKey(network, payTo, nonce) {
  return `${network}:nonce:${payTo}:${nonce}`;
}

export function outpointKey(network, txid, vout) {
  return `${network}:outpoint:${txid}:${vout}`;
}

async function confirmationsOf(rpc, txid, payIndex) {
  const out = await rpc('gettxout', [txid, payIndex, true]);
  if (out) return Number(out.confirmations ?? 0); // 0 = in mempool
  try {
    const t = await rpc('getrawtransaction', [txid, 1]); // needs -txindex once confirmed and spent
    return Number(t?.confirmations ?? 0);
  } catch {
    return -1; // unknown to this node
  }
}

/**
 * POST /settle.
 * opts = { store, now?, retentionSeconds? (default 86400), coreScriptCheck? }
 * Never rebroadcasts a payload it has already settled; resumes a pending one.
 */
export async function settleWithCore(rpc, body, opts) {
  const { store } = opts;
  const now = opts.now ?? Math.floor(Date.now() / 1000);
  const retention = opts.retentionSeconds ?? 86_400;
  const network = body?.paymentRequirements?.network ?? '';
  const fail = (errorReason, extra = {}) => ({ success: false, errorReason, transaction: '', network, ...extra });
  try {
    const st = checkStatic({ paymentPayload: body?.paymentPayload, paymentRequirements: body?.paymentRequirements, now, allowExpired: true });
    if (!st.isValid) return fail(st.invalidReason);
    const req = body.paymentRequirements;
    const nk = nonceKey(network, req.payTo, st.extra.nonce);
    const keep = Math.max(st.extra.validBefore, now) + retention;

    const observe = async (rec) => {
      const conf = await confirmationsOf(rpc, rec.txid, st.payIndex);
      const base = { transaction: rec.txid, network, ...(rec.payer ? { payer: rec.payer } : {}), amount: req.amount };
      if (conf < 0) return { success: false, errorReason: 'settlement_pending', ...base };
      if (conf >= st.extra.minConfirmations) {
        await store.set(nk, { ...rec, state: 'settled' }, keep);
        return { success: true, ...base };
      }
      return { success: false, errorReason: 'settlement_pending', ...base };
    };

    const prior = await store.get(nk, now);
    if (prior) {
      if (prior.txid !== st.txid) return fail('invalid_exact_dogecoin_nonce_used');
      if (prior.state === 'settled') return fail('duplicate_settlement', { transaction: prior.txid });
      if (prior.state === 'broadcast') return observe(prior); // settlement_pending retry
      return fail('duplicate_settlement', { transaction: prior.txid }); // in flight elsewhere
    }

    const v = await verifyWithCore(rpc, body, { now, coreScriptCheck: opts.coreScriptCheck });
    if (!v.isValid) return fail(v.invalidReason, v.payer ? { payer: v.payer } : {});

    // Claim the nonce and every outpoint before the first await on broadcast.
    const rec = { state: 'inflight', txid: st.txid, payer: v.payer };
    if (!(await store.claim(nk, rec, keep, now))) return fail('duplicate_settlement');
    const claimed = [];
    for (const input of st.tx.vin) {
      const ok = await store.claim(outpointKey(network, input.txid, input.vout), { txid: st.txid }, keep, now);
      if (!ok) {
        for (const k of claimed) await store.release(k);
        await store.release(nk);
        return fail('invalid_exact_dogecoin_input_claimed');
      }
      claimed.push(outpointKey(network, input.txid, input.vout));
    }

    try {
      await rpc('sendrawtransaction', [body.paymentPayload.payload.transaction, false]);
    } catch (e) {
      const code = e && typeof e === 'object' ? e.code : undefined;
      if (code === -27) {
        // "transaction already in block chain": these exact bytes are already mined.
      } else if (code === -26 || code === -25 || code === -22) {
        // Definitive rejection (policy, missing/spent inputs, decode): nothing landed.
        for (const k of claimed) await store.release(k);
        await store.release(nk);
        return fail('invalid_transaction_state', v.payer ? { payer: v.payer } : {});
      } else {
        // Unknown outcome: keep the claims, report pending with the txid we computed.
        await store.set(nk, { ...rec, state: 'broadcast' }, keep);
        return { success: false, errorReason: 'settlement_pending', transaction: st.txid, network, ...(v.payer ? { payer: v.payer } : {}) };
      }
    }
    const sent = { ...rec, state: 'broadcast' };
    await store.set(nk, sent, keep);
    return observe(sent);
  } catch {
    return fail('unexpected_settle_error');
  }
}

/** GET /supported entry for this facilitator. */
export function supportedKinds(networks = Object.keys(NETWORKS)) {
  return {
    kinds: networks.map((network) => ({ x402Version: X402_VERSION, scheme: SCHEME, network, extra: { assetTransferMethod: METHOD } })),
    extensions: [],
    signers: { 'bip122:*': [] },
  };
}
