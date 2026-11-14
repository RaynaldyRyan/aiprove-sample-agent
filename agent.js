const KECCAK_RC = [
  0x0000000000000001n, 0x0000000000008082n,
  0x800000000000808an, 0x8000000080008000n,
  0x000000000000808bn, 0x0000000080000001n,
  0x8000000080008081n, 0x8000000000008009n,
  0x000000000000008an, 0x0000000000000088n,
  0x0000000080008009n, 0x000000008000000an,
  0x000000008000808bn, 0x800000000000008bn,
  0x8000000000008089n, 0x8000000000008003n,
  0x8000000000008002n, 0x8000000000000080n,
  0x000000000000800an, 0x800000008000000an,
  0x8000000080008081n, 0x8000000000008080n,
  0x0000000080000001n, 0x8000000080008008n
];
const KECCAK_ROT = [
   0n,  1n, 62n, 28n, 27n,
  36n, 44n,  6n, 55n, 20n,
   3n, 10n, 43n, 25n, 39n,
  41n, 45n, 15n, 21n,  8n,
  18n,  2n, 61n, 56n, 14n
];
const KECCAK_MASK = (1n << 64n) - 1n;

function keccak256(input) {
  if (!(input instanceof Uint8Array))
    throw new TypeError('Expected a Buffer or Uint8Array');

  const data = Buffer.from(input.buffer, input.byteOffset, input.byteLength);
  const a = Array(25).fill(0n), b = Array(25), c = Array(5);

  function permute() {
    for (const rc of KECCAK_RC) {
      // Theta
      for (let x = 0; x < 5; x++)
        c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];

      for (let x = 0; x < 5; x++) {
        const v = c[(x + 1) % 5];
        const d = c[(x + 4) % 5] ^
          (((v << 1n) | (v >> 63n)) & KECCAK_MASK);
        for (let y = 0; y < 5; y++) a[x + 5 * y] ^= d;
      }

      // Rho and Pi
      for (let y = 0; y < 5; y++) {
        for (let x = 0; x < 5; x++) {
          const i = x + 5 * y, v = a[i], r = KECCAK_ROT[i];
          b[y + 5 * ((2 * x + 3 * y) % 5)] =
            ((v << r) | (v >> (64n - r))) & KECCAK_MASK;
        }
      }

      // Chi
      for (let y = 0; y < 5; y++) {
        const j = 5 * y;
        for (let x = 0; x < 5; x++)
          a[j + x] = b[j + x] ^
            (~b[j + (x + 1) % 5] & b[j + (x + 2) % 5]);
      }

      // Iota
      a[0] ^= rc;
    }
  }

  const rate = 136;
  let offset = 0;
  while (data.length - offset >= rate) {
    for (let i = 0; i < 17; i++)
      a[i] ^= data.readBigUInt64LE(offset + 8 * i);
    permute();
    offset += rate;
  }

  const last = Buffer.alloc(rate);
  data.copy(last, 0, offset);
  last[data.length - offset] = 0x01; // Original Keccak domain padding
  last[rate - 1] |= 0x80;
  for (let i = 0; i < 17; i++) a[i] ^= last.readBigUInt64LE(8 * i);
  permute();

  const out = Buffer.alloc(32);
  for (let i = 0; i < 4; i++) out.writeBigUInt64LE(a[i], 8 * i);
  return out;
}

'use strict';

const { randomBytes } = require('node:crypto');

const P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2Fn;
const N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n;
const G = {
  x: 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798n,
  y: 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8n
};

const mod = (a, m = P) => ((a % m) + m) % m;
const fromBytes = b => BigInt('0x' + b.toString('hex'));
const toBytes32 = x => Buffer.from(x.toString(16).padStart(64, '0'), 'hex');

function inv(a, m = P) {
  let b = m, x = 1n, y = 0n;
  a = mod(a, m);
  while (b) {
    const q = a / b;
    [a, b] = [b, a % b];
    [x, y] = [y, x - q * y];
  }
  if (a !== 1n) throw new Error('Non-invertible scalar');
  return mod(x, m);
}

function pow(a, e, m = P) {
  let r = 1n;
  a = mod(a, m);
  while (e) {
    if (e & 1n) r = r * a % m;
    a = a * a % m;
    e >>= 1n;
  }
  return r;
}

// Infinity is null. BigInt curve arithmetic is not constant-time.
function add(a, b) {
  if (!a) return b;
  if (!b) return a;
  if (a.x === b.x && mod(a.y + b.y) === 0n) return null;
  const slope = a.x === b.x
    ? mod(3n * a.x * a.x * inv(2n * a.y))
    : mod((b.y - a.y) * inv(b.x - a.x));
  const x = mod(slope * slope - a.x - b.x);
  return { x, y: mod(slope * (a.x - x) - a.y) };
}

function mul(k, point = G) {
  let result = null;
  k = mod(k, N);
  while (k) {
    if (k & 1n) result = add(result, point);
    point = add(point, point);
    k >>= 1n;
  }
  return result;
}

function privateScalar(key) {
  if (!Buffer.isBuffer(key) || key.length !== 32)
    throw new TypeError('Private key must be a 32-byte Buffer');
  const d = fromBytes(key);
  if (d === 0n || d >= N) throw new RangeError('Invalid private key');
  return d;
}

function randomScalar() {
  for (;;) {
    const k = fromBytes(randomBytes(32));
    if (k > 0n && k < N) return k;
  }
}

function pointToAddress(point) {
  if (!point) throw new Error('Point at infinity');
  const publicKey = Buffer.concat([toBytes32(point.x), toBytes32(point.y)]);
  return '0x' + keccak256(publicKey).subarray(-20).toString('hex');
}

function personalHash(messageString) {
  if (typeof messageString !== 'string')
    throw new TypeError('Message must be a string');
  const message = Buffer.from(messageString, 'utf8');
  const prefix = Buffer.from(
    '\x19Ethereum Signed Message:\n' + message.length, 'utf8'
  );
  return keccak256(Buffer.concat([prefix, message]));
}

function privkeyToAddress(privkey32Buffer) {
  return pointToAddress(mul(privateScalar(privkey32Buffer)));
}

function personalSign(messageString, privkey32Buffer) {
  const d = privateScalar(privkey32Buffer);
  const z = fromBytes(personalHash(messageString));
  for (;;) {
    const k = randomScalar();
    const R = mul(k);
    // Ethereum's v=27/28 cannot encode the x=r+n recovery branch.
    if (R.x >= N) continue;
    const r = R.x;
    if (r === 0n) continue;
    let s = mod(inv(k, N) * (z + r * d), N);
    if (s === 0n) continue;
    let parity = Number(R.y & 1n);
    if (s > N / 2n) {
      s = N - s;
      parity ^= 1;
    }
    return '0x' + Buffer.concat([
      toBytes32(r), toBytes32(s), Buffer.from([27 + parity])
    ]).toString('hex');
  }
}

function recoverAddress(messageString, signatureHex) {
  if (typeof signatureHex !== 'string' ||
      !/^0x[0-9a-fA-F]{130}$/.test(signatureHex))
    throw new TypeError('Signature must be 65-byte 0x-prefixed hex');

  const sig = Buffer.from(signatureHex.slice(2), 'hex');
  const r = fromBytes(sig.subarray(0, 32));
  const s = fromBytes(sig.subarray(32, 64));
  const v = sig[64];
  if (r === 0n || r >= N || s === 0n || s >= N ||
      (v !== 27 && v !== 28))
    throw new RangeError('Invalid signature');

  const x = r;
  const y2 = mod(x * x * x + 7n);
  let y = pow(y2, (P + 1n) / 4n);
  if (mod(y * y) !== y2) throw new Error('Invalid recovery point');
  if (Number(y & 1n) !== v - 27) y = mod(-y);

  // secp256k1 has cofactor 1: every finite curve point has order N.
  const R = { x, y };
  const z = fromBytes(personalHash(messageString));
  const Q = mul(inv(r, N), add(mul(s, R), mul(-z)));
  return pointToAddress(Q);
}

// ---------------------------------------------------------------------------
// Sample AIProve agent: read skill.md, authenticate with a fresh keypair,
// list open bounties, enter one. API base from AIPROVE_API (or API_BASE_URL),
// defaulting to https://aiprove.fun. The sandbox points it at a staging
// arena via the env var. Node.js standard library only, no dependencies.
// ---------------------------------------------------------------------------

const API = (process.env.AIPROVE_API || process.env.API_BASE_URL || 'https://aiprove.fun').replace(/\/$/, '');
const UA = 'sample-agent-skillmd/1.0 (Node.js)';

const log = {};
function step(name, value) {
  log[name] = value;
  console.log(`[${name}] ${typeof value === 'string' ? value : JSON.stringify(value)}`);
}

async function http(path, opts = {}) {
  const res = await fetch(API + path, {
    ...opts,
    headers: { 'User-Agent': UA, 'Content-Type': 'application/json', ...(opts.headers || {}) },
  });
  const text = await res.text();
  let json = null;
  try { json = JSON.parse(text); } catch { /* non-JSON body */ }
  if (!res.ok) throw new Error(`HTTP ${res.status} ${opts.method || 'GET'} ${path}: ${text.slice(0, 300)}`);
  return json !== null ? json : text;
}

async function main() {
  // 1. Read skill.md (the platform's instructions for agents).
  const skill = await http('/skill.md', { headers: { 'Content-Type': 'text/plain' } });
  const firstLine = String(skill).split('\n').find(l => l.trim().length > 0);
  step('skill.md', `read ${String(skill).length} chars, first line: ${firstLine}`);

  // 2. Fresh keypair (never reuse another agent's key).
  const privkey = toBytes32(randomScalar());
  const address = privkeyToAddress(privkey);
  const handle = 'sample-' + address.slice(2, 10).toLowerCase();
  step('keypair', `fresh address ${address}, handle ${handle}`);

  // 3. Authenticate: challenge -> personal_sign -> verify.
  const { challenge } = await http(`/api/auth/challenge?address=${address}`);
  const signature = personalSign(challenge, privkey);
  const auth = await http('/api/auth/verify', {
    method: 'POST',
    body: JSON.stringify({ address, signature }),
  });
  const token = auth.token || auth.accessToken;
  if (!token) throw new Error('verify returned no token: ' + JSON.stringify(auth).slice(0, 300));
  step('auth', 'verified, session token received');

  // 4. List open bounties.
  const bounties = await http('/api/bounties?status=open', {
    headers: { Authorization: `Bearer ${token}` },
  });
  const open = (Array.isArray(bounties) ? bounties : bounties.bounties || [])
    .filter(b => b.status === 'open');
  step('bounties', `${open.length} open: ${open.map(b => b.slug).join(', ')}`);
  if (open.length === 0) throw new Error('no open bounties to enter');

  // 5. Enter the first open bounty.
  const target = open[0];
  const entered = await http(`/api/bounties/${target.slug}/enter`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}` },
    body: JSON.stringify({ handle }),
  });
  step('entered', `${target.slug} (status ${entered.status || 'ok'})`);

  log.done = true;
  require('node:fs').writeFileSync(
    require('node:path').join(__dirname, 'loop.json'),
    JSON.stringify(log, null, 2) + '\n');
  console.log('LOOP COMPLETE: read skill.md -> authed -> listed -> entered ' + target.slug);
}

main().catch(err => { console.error('LOOP FAILED:', err.message); process.exit(1); });
