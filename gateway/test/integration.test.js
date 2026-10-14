'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const net = require('node:net');
const crypto = require('node:crypto');

const { loadConfig } = require('../src/config');
const { createGateway } = require('../src/server');
const { hashPassword, hotp, base32Decode, generateTotpSecret } = require('../src/auth');

const silent = { debug() {}, info() {}, warn() {}, error() {} };

/** Faux navigateur amont : HTTP + WebSocket (écho brut après handshake). */
function startUpstream() {
  const seen = [];
  const server = http.createServer((req, res) => {
    seen.push({ url: req.url, headers: req.headers });
    res.writeHead(200, { 'content-type': 'text/plain', 'x-upstream': 'yes' });
    res.end(`upstream:${req.method}:${req.url}`);
  });
  server.on('upgrade', (req, socket) => {
    seen.push({ url: req.url, headers: req.headers, ws: true });
    const accept = crypto
      .createHash('sha1')
      .update(req.headers['sec-websocket-key'] + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11')
      .digest('base64');
    socket.write(`HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${accept}\r\n\r\n`);
    socket.on('data', (d) => socket.write(d));
  });
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve({ server, seen, port: server.address().port })));
}

function request(port, { method = 'GET', path = '/', headers = {}, body } = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port, method, path, headers }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString() }));
    });
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

function wsHandshake(port, headers = {}) {
  return new Promise((resolve, reject) => {
    const socket = net.connect(port, '127.0.0.1', () => {
      const lines = [
        'GET /websockify HTTP/1.1',
        `Host: 127.0.0.1:${port}`,
        'Upgrade: websocket',
        'Connection: Upgrade',
        `Sec-WebSocket-Key: ${crypto.randomBytes(16).toString('base64')}`,
        'Sec-WebSocket-Version: 13',
        ...Object.entries(headers).map(([k, v]) => `${k}: ${v}`),
      ];
      socket.write(lines.join('\r\n') + '\r\n\r\n');
    });
    let buf = '';
    socket.on('data', function onData(d) {
      buf += d.toString();
      if (buf.includes('\r\n\r\n')) {
        socket.removeListener('data', onData);
        resolve({ socket, status: Number(buf.split(' ')[1]), raw: buf });
      }
    });
    socket.on('error', reject);
  });
}

async function setup(env = {}) {
  const upstream = await startUpstream();
  const config = loadConfig({
    AUTH_USERNAME: 'nathan',
    AUTH_PASSWORD_HASH: await hashPassword('motdepasse-solide', { N: 1024, r: 8, p: 1, keyLen: 32 }),
    UPSTREAM_URL: `http://127.0.0.1:${upstream.port}`,
    TLS_MODE: 'off',
    LOGIN_FAILURE_DELAY_MS: '0',
    PUBLIC_IP_AUTODETECT: 'false',
    ...env,
  });
  const gateway = await createGateway(config, { logger: silent, dockerGateways: [] });
  const { port } = await gateway.listen(0, '127.0.0.1');
  return {
    port,
    upstream,
    gateway,
    async close() {
      await gateway.close();
      upstream.server.closeAllConnections();
      // Les sockets « upgradés » ne sont pas comptés de façon fiable par close() : on n'attend pas.
      upstream.server.close();
    },
  };
}

async function login(port, { username = 'nathan', password = 'motdepasse-solide', totp, headers = {} } = {}) {
  const form = new URLSearchParams({ username, password, next: '/app?x=1' });
  if (totp) form.set('totp', totp);
  return request(port, {
    method: 'POST',
    path: '/__auth/login',
    headers: { 'content-type': 'application/x-www-form-urlencoded', origin: `http://127.0.0.1:${port}`, ...headers },
    body: form.toString(),
  });
}

test('flux complet : redirection, connexion, proxy HTTP et WebSocket, déconnexion', async () => {
  const ctx = await setup();
  try {
    const anon = await request(ctx.port, { headers: { accept: 'text/html' } });
    assert.equal(anon.status, 302);
    assert.match(anon.headers.location, /^\/__auth\/login\?next=/);

    const api = await request(ctx.port, { path: '/data' });
    assert.equal(api.status, 401);

    const page = await request(ctx.port, { path: '/__auth/login' });
    assert.equal(page.status, 200);
    assert.match(page.body, /<form/);
    assert.match(page.headers['content-security-policy'], /frame-ancestors 'none'/);

    const bad = await login(ctx.port, { password: 'faux' });
    assert.equal(bad.status, 401);
    assert.match(bad.body, /invalides/);

    const ok = await login(ctx.port);
    assert.equal(ok.status, 303);
    assert.equal(ok.headers.location, '/app?x=1');
    const setCookie = ok.headers['set-cookie'][0];
    assert.match(setCookie, /HttpOnly/);
    assert.match(setCookie, /SameSite=Strict/);
    const cookie = setCookie.split(';')[0];

    const proxied = await request(ctx.port, { path: '/app?x=1', headers: { cookie: `${cookie}; other=1` } });
    assert.equal(proxied.status, 200);
    assert.equal(proxied.body, 'upstream:GET:/app?x=1');
    assert.equal(proxied.headers['x-upstream'], 'yes');
    const seen = ctx.upstream.seen.at(-1);
    assert.equal(seen.headers.cookie, 'other=1', 'le cookie de session ne fuit pas vers l\'amont');
    assert.equal(seen.headers['x-forwarded-for'], '127.0.0.1');

    const wsAnon = await wsHandshake(ctx.port);
    assert.equal(wsAnon.status, 401);
    wsAnon.socket.destroy();

    const ws = await wsHandshake(ctx.port, { Cookie: cookie });
    assert.equal(ws.status, 101);
    const echoed = await new Promise((resolve) => {
      ws.socket.once('data', (d) => resolve(d.toString()));
      ws.socket.write('ping');
    });
    assert.equal(echoed, 'ping');

    const closed = new Promise((r) => ws.socket.once('close', r));
    const out = await request(ctx.port, { path: '/__auth/logout', headers: { cookie } });
    assert.equal(out.status, 303);
    await closed; // la déconnexion coupe les WebSockets de la session

    const after = await request(ctx.port, { path: '/data', headers: { cookie } });
    assert.equal(after.status, 401);
  } finally {
    await ctx.close();
  }
});

test('connexion refusée depuis une origine étrangère (CSRF)', async () => {
  const ctx = await setup();
  try {
    const res = await login(ctx.port, { headers: { origin: 'https://evil.example' } });
    assert.equal(res.status, 403);
  } finally {
    await ctx.close();
  }
});

test('verrouillage après trop d\'échecs', async () => {
  const ctx = await setup({ LOGIN_MAX_ATTEMPTS: '3' });
  try {
    await login(ctx.port, { password: 'a' });
    await login(ctx.port, { password: 'b' });
    const third = await login(ctx.port, { password: 'c' });
    assert.equal(third.status, 429);
    const good = await login(ctx.port);
    assert.equal(good.status, 429, 'même le bon mot de passe est refusé pendant le verrouillage');
  } finally {
    await ctx.close();
  }
});

test('TOTP requis quand configuré', async () => {
  const secret = generateTotpSecret();
  const ctx = await setup({ TOTP_SECRET: secret });
  try {
    const page = await request(ctx.port, { path: '/__auth/login' });
    assert.match(page.body, /name="totp"/);
    const missing = await login(ctx.port);
    assert.equal(missing.status, 401);
    const code = hotp(base32Decode(secret), Math.floor(Date.now() / 30_000));
    const ok = await login(ctx.port, { totp: code });
    assert.equal(ok.status, 303);
  } finally {
    await ctx.close();
  }
});

test('restriction IP : liste blanche, IP publique du serveur et localhost', async () => {
  const ctx = await setup({
    IP_RESTRICTION_ENABLED: 'true',
    IP_ALLOWLIST: '198.51.100.0/24',
    SERVER_PUBLIC_IP: '203.0.113.7',
    TRUSTED_PROXIES: '127.0.0.1',
  });
  try {
    await ctx.gateway.publicIp.refresh();
    const via = (ip) => request(ctx.port, { path: '/__auth/login', headers: { 'x-forwarded-for': ip } });

    assert.equal((await via('8.8.8.8')).status, 403);
    assert.equal((await via('198.51.100.9')).status, 200);
    assert.equal((await via('203.0.113.7')).status, 200);
    assert.equal((await request(ctx.port, { path: '/__auth/login' })).status, 200, 'localhost toujours autorisé');

    const ws = await wsHandshake(ctx.port, { 'X-Forwarded-For': '8.8.8.8' });
    assert.equal(ws.status, 403);
    ws.socket.destroy();
  } finally {
    await ctx.close();
  }
});

test('X-Forwarded-For ignoré si la connexion ne vient pas d\'un proxy de confiance', async () => {
  const ctx = await setup({ IP_RESTRICTION_ENABLED: 'true', TRUSTED_PROXIES: '10.9.9.9' });
  try {
    // Le client est 127.0.0.1 (autorisé) : l'en-tête usurpé ne doit pas le faire passer pour une autre IP.
    const res = await request(ctx.port, { path: '/__auth/login', headers: { 'x-forwarded-for': '8.8.8.8' } });
    assert.equal(res.status, 200);
  } finally {
    await ctx.close();
  }
});

test('502 lisible quand le navigateur est arrêté', async () => {
  const ctx = await setup();
  try {
    const ok = await login(ctx.port);
    const cookie = ok.headers['set-cookie'][0].split(';')[0];
    ctx.upstream.server.closeAllConnections();
    await new Promise((r) => ctx.upstream.server.close(r));
    const res = await request(ctx.port, { path: '/', headers: { cookie } });
    assert.equal(res.status, 502);
    assert.match(res.body, /Navigateur indisponible/);
  } finally {
    await ctx.gateway.close();
  }
});
