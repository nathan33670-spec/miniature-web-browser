'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { IpSet, AccessControl, resolveClientIp, normalizeIp, detectDockerGateways } = require('../src/ipfilter');
const {
  hashPassword,
  verifyPassword,
  hotp,
  TotpVerifier,
  base32Encode,
  base32Decode,
  SessionStore,
  LoginLimiter,
} = require('../src/auth');
const { loadConfig } = require('../src/config');
const { safeNext } = require('../src/server');
const { removeCookie } = require('../src/proxy');

test('normalizeIp gère IPv4-mapped, crochets et zones', () => {
  assert.equal(normalizeIp('::ffff:192.168.1.10'), '192.168.1.10');
  assert.equal(normalizeIp('[2001:db8::1]'), '2001:db8::1');
  assert.equal(normalizeIp('fe80::1%eth0'), 'fe80::1');
  assert.equal(normalizeIp('pas-une-ip'), '');
});

test('IpSet : adresses et CIDR IPv4/IPv6', () => {
  const set = new IpSet(['192.168.1.0/24', '10.0.0.5', '2001:db8::/32']);
  assert.ok(set.has('192.168.1.200'));
  assert.ok(set.has('::ffff:192.168.1.3'));
  assert.ok(!set.has('192.168.2.1'));
  assert.ok(set.has('10.0.0.5'));
  assert.ok(!set.has('10.0.0.6'));
  assert.ok(set.has('2001:db8:1234::1'));
  assert.ok(!set.has('2001:db9::1'));
  assert.throws(() => new IpSet(['300.1.1.1']));
  assert.throws(() => new IpSet(['10.0.0.0/33']));
});

test('AccessControl : localhost, NAS et IP publique toujours autorisés', () => {
  const ac = new AccessControl({ enabled: true, allowlist: ['198.51.100.0/24'], alwaysAllowed: ['192.168.1.20', '172.18.0.1'] });
  ac.setDynamic(['203.0.113.7']);
  assert.ok(ac.check('127.0.0.1'));
  assert.ok(ac.check('::1'));
  assert.ok(ac.check('192.168.1.20'));
  assert.ok(ac.check('172.18.0.1'));
  assert.ok(ac.check('203.0.113.7'));
  assert.ok(ac.check('198.51.100.42'));
  assert.equal(ac.check('8.8.8.8'), null);
  assert.equal(ac.check('192.168.1.21'), null);
  const off = new AccessControl({ enabled: false });
  assert.ok(off.check('8.8.8.8'));
});

test('resolveClientIp ne fait confiance à X-Forwarded-For que depuis un proxy de confiance', () => {
  const trusted = new IpSet(['172.18.0.1']);
  assert.equal(resolveClientIp('8.8.8.8', '127.0.0.1', trusted), '8.8.8.8');
  assert.equal(resolveClientIp('172.18.0.1', '1.2.3.4', trusted), '1.2.3.4');
  assert.equal(resolveClientIp('172.18.0.1', '127.0.0.1, 1.2.3.4', trusted), '1.2.3.4');
  assert.equal(resolveClientIp('172.18.0.1', '1.2.3.4, 172.18.0.1', trusted), '1.2.3.4');
  assert.equal(resolveClientIp('172.18.0.1', 'garbage', trusted), '172.18.0.1');
  assert.equal(resolveClientIp('172.18.0.1', undefined, trusted), '172.18.0.1');
  assert.equal(resolveClientIp('::ffff:9.9.9.9', '1.1.1.1', new IpSet()), '9.9.9.9');
});

test('detectDockerGateways lit la route par défaut', () => {
  const file = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'rb-')), 'route');
  fs.writeFileSync(
    file,
    'Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n' +
      'eth0\t00000000\t010012AC\t0003\t0\t0\t0\t00000000\t0\t0\t0\n' +
      'eth0\t000012AC\t00000000\t0001\t0\t0\t0\t0000FFFF\t0\t0\t0\n'
  );
  assert.deepEqual(detectDockerGateways(file), ['172.18.0.1']);
  assert.deepEqual(detectDockerGateways('/nonexistent'), []);
});

test('hash et vérification de mot de passe scrypt', async () => {
  const hash = await hashPassword('correct horse battery staple', { N: 1024, r: 8, p: 1, keyLen: 32 });
  assert.match(hash, /^scrypt:1024:8:1:[\w-]+:[\w-]+$/);
  assert.ok(!hash.includes('$'));
  assert.ok(await verifyPassword('correct horse battery staple', hash));
  assert.ok(!(await verifyPassword('mauvais', hash)));
  assert.ok(!(await verifyPassword('x', 'scrypt:invalide')));
});

test('TOTP conforme aux vecteurs RFC 6238 et anti-rejeu', () => {
  const secret = Buffer.from('12345678901234567890');
  assert.equal(hotp(secret, Math.floor(59 / 30)), '287082');
  assert.equal(hotp(secret, Math.floor(1111111109 / 30)), '081804');
  assert.deepEqual(base32Decode(base32Encode(secret)), secret);

  const verifier = new TotpVerifier(base32Encode(secret));
  const now = 1111111109 * 1000;
  assert.ok(verifier.verify('081804', now));
  assert.ok(!verifier.verify('081804', now), 'un code ne peut être réutilisé');
  assert.ok(!verifier.verify('000000', now));
  assert.ok(!verifier.verify('abc', now));
});

test('SessionStore : expiration absolue et inactivité', () => {
  const store = new SessionStore({ ttlMs: 10_000, idleMs: 5_000 });
  const token = store.create();
  assert.ok(store.get(token));
  assert.equal(store.get('inconnu'), null);
  const session = store.sessions.values().next().value;
  session.lastSeen -= 6_000;
  assert.equal(store.get(token), null, 'expirée par inactivité');

  const t2 = store.create();
  const s2 = [...store.sessions.values()].at(-1);
  s2.createdAt -= 11_000;
  assert.equal(store.get(t2), null, 'expirée par durée maximale');

  const t3 = store.create();
  store.destroy(t3);
  assert.equal(store.get(t3), null);
});

test('LoginLimiter verrouille après N échecs', () => {
  const limiter = new LoginLimiter({ maxAttempts: 3, windowMs: 60_000, lockoutMs: 120_000 });
  const now = 1_000_000;
  assert.equal(limiter.recordFailure('1.1.1.1', now), false);
  assert.equal(limiter.recordFailure('1.1.1.1', now), false);
  assert.equal(limiter.recordFailure('1.1.1.1', now), true);
  assert.ok(limiter.lockedUntil('1.1.1.1', now + 1000));
  assert.equal(limiter.lockedUntil('2.2.2.2', now), 0);
  assert.equal(limiter.lockedUntil('1.1.1.1', now + 121_000), 0);
});

test('safeNext empêche les redirections ouvertes', () => {
  assert.equal(safeNext('/page?x=1'), '/page?x=1');
  assert.equal(safeNext('//evil.com'), '/');
  assert.equal(safeNext('/\\evil.com'), '/');
  assert.equal(safeNext('https://evil.com'), '/');
  assert.equal(safeNext('/__auth/logout'), '/');
});

test('removeCookie retire uniquement le cookie de session', () => {
  assert.equal(removeCookie('a=1; rb_session=xyz; b=2', 'rb_session'), 'a=1; b=2');
  assert.equal(removeCookie('rb_session=xyz', 'rb_session'), undefined);
});

test('loadConfig exige un mot de passe et valide les options', () => {
  assert.throws(() => loadConfig({}), /Aucun mot de passe/);
  assert.throws(() => loadConfig({ AUTH_PASSWORD_HASH: '$2b$10$abc' }), /scrypt/);
  const c = loadConfig({ AUTH_PASSWORD: 'x', IP_RESTRICTION_ENABLED: 'true', IP_ALLOWLIST: '1.2.3.4, 10.0.0.0/8' });
  assert.equal(c.access.enabled, true);
  assert.deepEqual(c.access.allowlist, ['1.2.3.4', '10.0.0.0/8']);
  assert.equal(c.access.ipv4Only, true, 'IPv4 uniquement par défaut');
  assert.throws(() => loadConfig({ AUTH_PASSWORD: 'x', IP_ALLOWLIST: '2a01:cb00::/32' }), /IPv6/);
  assert.throws(() => loadConfig({ AUTH_PASSWORD: 'x', LISTEN_HOST: '::' }), /IPv6/);
  assert.doesNotThrow(() => loadConfig({ AUTH_PASSWORD: 'x', IPV4_ONLY: 'false', IP_ALLOWLIST: '2a01:cb00::/32' }));
});
