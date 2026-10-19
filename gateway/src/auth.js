'use strict';

const crypto = require('node:crypto');
const { promisify } = require('node:util');

const scrypt = promisify(crypto.scrypt);

// ---------------------------------------------------------------------------
// Mots de passe (scrypt). Format : scrypt:N:r:p:sel:hash (base64url).
// Le séparateur ":" évite le "$" qui serait interprété par docker compose.
// ---------------------------------------------------------------------------

const SCRYPT_DEFAULTS = { N: 2 ** 15, r: 8, p: 1, keyLen: 64 };

function scryptOptions(N, r, p) {
  return { N, r, p, maxmem: 256 * N * r * p + 1024 * 1024 };
}

async function hashPassword(password, { N, r, p, keyLen } = SCRYPT_DEFAULTS) {
  const salt = crypto.randomBytes(16);
  const key = await scrypt(String(password).normalize('NFKC'), salt, keyLen, scryptOptions(N, r, p));
  return ['scrypt', N, r, p, salt.toString('base64url'), key.toString('base64url')].join(':');
}

async function verifyPassword(password, stored) {
  const parts = String(stored).split(':');
  if (parts.length !== 6 || parts[0] !== 'scrypt') return false;
  const [, N, r, p, saltB64, keyB64] = parts;
  const expected = Buffer.from(keyB64, 'base64url');
  const salt = Buffer.from(saltB64, 'base64url');
  if (!expected.length || !salt.length) return false;
  let actual;
  try {
    actual = await scrypt(String(password).normalize('NFKC'), salt, expected.length, scryptOptions(+N, +r, +p));
  } catch {
    return false;
  }
  return crypto.timingSafeEqual(actual, expected);
}

function safeEqual(a, b) {
  const ha = crypto.createHash('sha256').update(String(a)).digest();
  const hb = crypto.createHash('sha256').update(String(b)).digest();
  return crypto.timingSafeEqual(ha, hb);
}

// ---------------------------------------------------------------------------
// TOTP (RFC 6238 : SHA-1, 6 chiffres, période de 30 s)
// ---------------------------------------------------------------------------

const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function base32Encode(buf) {
  let bits = 0;
  let value = 0;
  let out = '';
  for (const byte of buf) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += B32[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += B32[(value << (5 - bits)) & 31];
  return out;
}

function base32Decode(str) {
  const clean = String(str).toUpperCase().replace(/=+$/, '').replace(/\s+/g, '');
  let bits = 0;
  let value = 0;
  const out = [];
  for (const ch of clean) {
    const idx = B32.indexOf(ch);
    if (idx === -1) throw new Error('Caractère base32 invalide');
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

function generateTotpSecret() {
  return base32Encode(crypto.randomBytes(20));
}

function hotp(secret, counter, digits = 6) {
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(BigInt(counter));
  const hmac = crypto.createHmac('sha1', secret).update(buf).digest();
  const offset = hmac[hmac.length - 1] & 0xf;
  const code = (hmac.readUInt32BE(offset) & 0x7fffffff) % 10 ** digits;
  return String(code).padStart(digits, '0');
}

class TotpVerifier {
  constructor(base32Secret, { period = 30, window = 1 } = {}) {
    this.secret = base32Decode(base32Secret);
    this.period = period;
    this.window = window;
    this.lastCounter = -1; // anti-rejeu : un code ne sert qu'une fois
  }

  verify(code, now = Date.now()) {
    const clean = String(code || '').replace(/\s+/g, '');
    if (!/^\d{6}$/.test(clean)) return false;
    const current = Math.floor(now / 1000 / this.period);
    for (let delta = -this.window; delta <= this.window; delta++) {
      const counter = current + delta;
      if (counter <= this.lastCounter) continue;
      if (safeEqual(hotp(this.secret, counter), clean)) {
        this.lastCounter = counter;
        return true;
      }
    }
    return false;
  }
}

// ---------------------------------------------------------------------------
// Sessions (en mémoire : un redémarrage de la passerelle déconnecte)
// ---------------------------------------------------------------------------

class SessionStore {
  constructor({ ttlMs, idleMs }) {
    this.ttlMs = ttlMs;
    this.idleMs = idleMs;
    this.sessions = new Map();
  }

  static key(token) {
    return crypto.createHash('sha256').update(String(token)).digest('hex');
  }

  create(meta = {}) {
    const token = crypto.randomBytes(32).toString('base64url');
    const now = Date.now();
    this.sessions.set(SessionStore.key(token), {
      ...meta,
      createdAt: now,
      lastSeen: now,
      sockets: new Set(),
    });
    return token;
  }

  isExpired(session, now = Date.now()) {
    return now - session.createdAt > this.ttlMs || now - session.lastSeen > this.idleMs;
  }

  get(token, { touch = true } = {}) {
    if (!token) return null;
    const key = SessionStore.key(token);
    const session = this.sessions.get(key);
    if (!session) return null;
    if (this.isExpired(session)) {
      this.destroyByKey(key);
      return null;
    }
    if (touch) session.lastSeen = Date.now();
    return session;
  }

  attachSocket(session, socket) {
    session.sockets.add(socket);
    socket.once('close', () => session.sockets.delete(socket));
  }

  destroy(token) {
    if (token) this.destroyByKey(SessionStore.key(token));
  }

  destroyByKey(key) {
    const session = this.sessions.get(key);
    if (!session) return;
    this.sessions.delete(key);
    for (const socket of session.sockets) socket.destroy();
  }

  /** Purge les sessions expirées et ferme leurs tunnels d'affichage encore ouverts. */
  sweep(now = Date.now()) {
    for (const [key, session] of this.sessions) {
      // Un tunnel d'affichage ouvert compte comme activité.
      if (session.sockets.size > 0) session.lastSeen = now;
      if (this.isExpired(session, now)) this.destroyByKey(key);
    }
  }
}

// ---------------------------------------------------------------------------
// Anti-bruteforce par IP
// ---------------------------------------------------------------------------

class LoginLimiter {
  constructor({ maxAttempts, windowMs, lockoutMs }) {
    this.maxAttempts = maxAttempts;
    this.windowMs = windowMs;
    this.lockoutMs = lockoutMs;
    this.entries = new Map();
  }

  lockedUntil(ip, now = Date.now()) {
    const entry = this.entries.get(ip);
    return entry && entry.lockedUntil > now ? entry.lockedUntil : 0;
  }

  recordFailure(ip, now = Date.now()) {
    let entry = this.entries.get(ip);
    if (!entry || now - entry.firstAt > this.windowMs) {
      entry = { count: 0, firstAt: now, lockedUntil: 0 };
      this.entries.set(ip, entry);
    }
    entry.count += 1;
    if (this.maxAttempts > 0 && entry.count >= this.maxAttempts) {
      entry.lockedUntil = now + this.lockoutMs;
      entry.count = 0;
      entry.firstAt = now;
      return true;
    }
    return false;
  }

  recordSuccess(ip) {
    this.entries.delete(ip);
  }

  sweep(now = Date.now()) {
    for (const [ip, entry] of this.entries) {
      if (entry.lockedUntil <= now && now - entry.firstAt > this.windowMs) this.entries.delete(ip);
    }
  }
}

module.exports = {
  hashPassword,
  verifyPassword,
  safeEqual,
  base32Encode,
  base32Decode,
  generateTotpSecret,
  hotp,
  TotpVerifier,
  SessionStore,
  LoginLimiter,
};
