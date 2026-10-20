'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const net = require('node:net');
const crypto = require('node:crypto');

const { loadConfig } = require('../src/config');
const { createGateway } = require('../src/server');
const { hashPassword, hotp, base32Decode, generateTotpSecret } = require('../src/auth');
const { InstructionParser, encodeInstruction } = require('../src/guac');

const silent = { debug() {}, info() {}, warn() {}, error() {} };

/**
 * Faux guacd : négociation VNC, puis envoie "sync" et répond "echo" à chaque
 * instruction "test" reçue du navigateur.
 */
function startFakeGuacd() {
  const state = { connects: [], sizes: [], received: [], sockets: new Set() };
  const server = net.createServer((socket) => {
    state.sockets.add(socket);
    socket.on('close', () => state.sockets.delete(socket));
    socket.setEncoding('utf8');
    const parser = new InstructionParser();
    socket.on('data', (chunk) => {
      for (const ins of parser.push(chunk)) {
        if (ins.opcode === 'select') {
          socket.write(encodeInstruction('args', 'VERSION_1_5_0', 'hostname', 'port', 'password'));
        } else if (ins.opcode === 'size') {
          state.sizes.push(ins.args);
        } else if (ins.opcode === 'connect') {
          state.connects.push(ins.args);
          socket.write(encodeInstruction('ready', '$fake') + encodeInstruction('sync', '1'));
        } else {
          state.received.push(ins);
          if (ins.opcode === 'test') socket.write(encodeInstruction('echo', ...ins.args));
        }
      }
    });
    socket.on('error', () => {});
  });
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve({ server, state, port: server.address().port })));
}

function request(port, { method = 'GET', path = '/', headers = {}, body } = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port, method, path, headers }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        const rawBody = Buffer.concat(chunks);
        resolve({ status: res.statusCode, headers: res.headers, body: rawBody.toString(), rawBody });
      });
    });
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

function rawUpgrade(port) {
  return new Promise((resolve, reject) => {
    const socket = net.connect(port, '127.0.0.1', () => {
      socket.write(
        'GET /tunnel HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n' +
          `Sec-WebSocket-Key: ${crypto.randomBytes(16).toString('base64')}\r\nSec-WebSocket-Version: 13\r\n\r\n`
      );
    });
    let buf = '';
    socket.on('data', (d) => (buf += d));
    socket.on('close', () => resolve(Number(buf.split(' ')[1])));
    socket.on('error', reject);
  });
}

async function setup(env = {}) {
  const guacd = await startFakeGuacd();
  const config = loadConfig({
    AUTH_USERNAME: 'nathan',
    AUTH_PASSWORD_HASH: await hashPassword('motdepasse-solide', { N: 1024, r: 8, p: 1, keyLen: 32 }),
    GUACD_HOST: '127.0.0.1',
    GUACD_PORT: String(guacd.port),
    DESKTOP_HOST: 'desktop',
    DESKTOP_VNC_PASSWORD: 'secret',
    TLS_MODE: 'off',
    LOGIN_FAILURE_DELAY_MS: '0',
    PUBLIC_IP_AUTODETECT: 'false',
    ...env,
  });
  const gateway = await createGateway(config, { logger: silent, dockerGateways: [] });
  const { port } = await gateway.listen(0, '127.0.0.1');
  return {
    port,
    guacd,
    gateway,
    async close() {
      await gateway.close();
      for (const s of guacd.state.sockets) s.destroy();
      await new Promise((r) => guacd.server.close(r));
    },
  };
}

async function login(port, { username = 'nathan', password = 'motdepasse-solide', totp, headers = {} } = {}) {
  const form = new URLSearchParams({ username, password, next: '/' });
  if (totp) form.set('totp', totp);
  return request(port, {
    method: 'POST',
    path: '/__auth/login',
    headers: { 'content-type': 'application/x-www-form-urlencoded', origin: `http://127.0.0.1:${port}`, ...headers },
    body: form.toString(),
  });
}

async function loggedIn(port) {
  const res = await login(port);
  assert.equal(res.status, 303);
  return res.headers['set-cookie'][0].split(';')[0];
}

async function openTunnel(port, cookie) {
  const res = await request(port, {
    method: 'POST',
    path: '/tunnel?connect',
    headers: { cookie, 'content-type': 'application/x-www-form-urlencoded' },
    body: 'width=1280&height=720&dpi=96&timezone=Europe/Paris',
  });
  return { ...res, uuid: res.body, token: res.headers['guacamole-tunnel-token'] };
}

test('flux complet : connexion, page client, tunnel HTTP lecture/écriture, déconnexion', async () => {
  const ctx = await setup();
  try {
    const anon = await request(ctx.port, { headers: { accept: 'text/html' } });
    assert.equal(anon.status, 302);
    assert.match(anon.headers.location, /^\/__auth\/login\?next=/);
    assert.equal((await request(ctx.port, { method: 'POST', path: '/tunnel?connect' })).status, 401);

    const bad = await login(ctx.port, { password: 'faux' });
    assert.equal(bad.status, 401);

    const cookie = await loggedIn(ctx.port);

    const page = await request(ctx.port, { headers: { cookie } });
    assert.equal(page.status, 200);
    assert.match(page.body, /client\.js/);
    assert.match(page.headers['content-security-policy'], /script-src 'self'/);

    const lib = await request(ctx.port, { path: '/static/guacamole-common.js', headers: { cookie, 'accept-encoding': 'gzip' } });
    assert.equal(lib.status, 200);
    assert.equal(lib.headers['content-encoding'], 'gzip');
    const notModified = await request(ctx.port, { path: '/static/client.js', headers: { cookie, 'if-none-match': (await request(ctx.port, { path: '/static/client.js', headers: { cookie } })).headers.etag } });
    assert.equal(notModified.status, 304);

    // Ouverture du tunnel
    const tunnel = await openTunnel(ctx.port, cookie);
    assert.equal(tunnel.status, 200);
    assert.match(tunnel.uuid, /^[0-9a-f-]{36}$/);
    assert.ok(tunnel.token);
    assert.deepEqual(ctx.guacd.state.sizes[0], ['1280', '720', '96']);
    assert.deepEqual(ctx.guacd.state.connects[0], ['VERSION_1_5_0', 'desktop', '5900', 'secret']);

    const tunnelHeaders = { cookie, 'guacamole-tunnel-token': tunnel.token };

    // Lecture : la réponse se termine d'elle-même par "0.;" (compatible proxys qui bufferisent)
    const read1 = await request(ctx.port, { path: `/tunnel?read:${tunnel.uuid}:0`, headers: tunnelHeaders });
    assert.equal(read1.status, 200);
    assert.equal(read1.headers['x-accel-buffering'], 'no');
    assert.equal(read1.body, '4.sync,1.1;0.;');

    // Écriture puis lecture de la réponse
    const write = await request(ctx.port, {
      method: 'POST',
      path: `/tunnel?write:${tunnel.uuid}`,
      headers: { ...tunnelHeaders, 'content-type': 'application/octet-stream' },
      body: '3.nop;4.test,5.hello;',
    });
    assert.equal(write.status, 200);
    const read2 = await request(ctx.port, { path: `/tunnel?read:${tunnel.uuid}:1`, headers: tunnelHeaders });
    assert.equal(read2.body, '4.echo,5.hello;0.;');
    assert.deepEqual(ctx.guacd.state.received.map((i) => i.opcode), ['audio', 'video', 'image', 'timezone', 'nop', 'test']);
    assert.deepEqual(ctx.guacd.state.received.find((i) => i.opcode === 'timezone').args, ['Europe/Paris']);

    // Mauvais jeton ou autre session : refus
    const wrongToken = await request(ctx.port, { path: `/tunnel?read:${tunnel.uuid}:2`, headers: { cookie, 'guacamole-tunnel-token': 'x' } });
    assert.equal(wrongToken.status, 403);
    assert.equal(wrongToken.headers['guacamole-status-code'], String(0x0303));
    const otherCookie = await loggedIn(ctx.port);
    const otherSession = await request(ctx.port, {
      path: `/tunnel?read:${tunnel.uuid}:2`,
      headers: { cookie: otherCookie, 'guacamole-tunnel-token': tunnel.token },
    });
    assert.equal(otherSession.status, 403);
    const unknown = await request(ctx.port, { path: `/tunnel?read:${crypto.randomUUID()}:0`, headers: tunnelHeaders });
    assert.equal(unknown.status, 404);
    assert.equal(unknown.headers['guacamole-status-code'], String(0x0204));

    // Les WebSockets ne sont plus acceptés
    assert.equal(await rawUpgrade(ctx.port), 404);

    // Déconnexion : le tunnel et la connexion guacd sont fermés
    const guacdClosed = new Promise((resolve) => {
      const [sock] = ctx.guacd.state.sockets;
      sock.once('close', resolve);
    });
    await request(ctx.port, { path: '/__auth/logout', headers: { cookie } });
    await guacdClosed;
    assert.equal((await request(ctx.port, { path: `/tunnel?read:${tunnel.uuid}:3`, headers: tunnelHeaders })).status, 401);
  } finally {
    await ctx.close();
  }
});

test('lectures en parallèle : servies dans l\'ordre, même si les requêtes arrivent dans le désordre', async () => {
  const ctx = await setup();
  try {
    const cookie = await loggedIn(ctx.port);
    const tunnel = await openTunnel(ctx.port, cookie);
    const headers = { cookie, 'guacamole-tunnel-token': tunnel.token };
    const read = (n) => request(ctx.port, { path: `/tunnel?read:${tunnel.uuid}:${n}`, headers });
    const write = (n, body) => request(ctx.port, { method: 'POST', path: `/tunnel?write:${tunnel.uuid}:${n}`, headers, body });

    // La lecture 1 arrive avant la 0 : la 0 reçoit quand même les premières données.
    const r1 = read(1);
    await new Promise((r) => setTimeout(r, 30));
    const r0 = read(0);
    assert.equal((await r0).body, '4.sync,1.1;0.;');
    const r2 = read(2);

    // Écritures dans le désordre : guacd les reçoit dans l'ordre 0, 1.
    await write(1, '4.test,1.b;');
    await new Promise((r) => setTimeout(r, 30));
    assert.equal(ctx.guacd.state.received.filter((i) => i.opcode === 'test').length, 0, 'écriture 1 retenue tant que la 0 manque');
    await write(0, '4.test,1.a;');
    assert.equal((await r1).body, '4.echo,1.a;4.echo,1.b;0.;', 'réponses regroupées, dans l\'ordre des écritures');
    const tests = ctx.guacd.state.received.filter((i) => i.opcode === 'test').map((i) => i.args[0]);
    assert.deepEqual(tests, ['a', 'b']);
    await write(2, '4.test,1.c;');
    assert.equal((await r2).body, '4.echo,1.c;0.;', 'la lecture suivante prend le relais');

    // Numéro déjà servi : refusé.
    assert.equal((await read(0)).status, 400);
  } finally {
    await ctx.close();
  }
});

test('réponses compressées (gzip) et caractères hors BMP convertis pour le navigateur', async () => {
  const ctx = await setup();
  try {
    const cookie = await loggedIn(ctx.port);
    const tunnel = await openTunnel(ctx.port, cookie);
    const headers = { cookie, 'guacamole-tunnel-token': tunnel.token };
    await request(ctx.port, { path: `/tunnel?read:${tunnel.uuid}:0`, headers });

    // Le navigateur compte en unités UTF-16 ("😀" = 2) ; guacd en points de code (1).
    const big = 'x'.repeat(5000);
    const reply = request(ctx.port, { path: `/tunnel?read:${tunnel.uuid}:1`, headers: { ...headers, 'accept-encoding': 'gzip' }, raw: true });
    await request(ctx.port, { method: 'POST', path: `/tunnel?write:${tunnel.uuid}:0`, headers, body: `4.test,${big.length + 2}.${big}😀;` });
    const res = await reply;
    assert.equal(res.headers['content-encoding'], 'gzip');
    const body = require('node:zlib').gunzipSync(res.rawBody).toString();
    assert.equal(body, `4.echo,${big.length + 2}.${big}😀;0.;`);
    const sent = ctx.guacd.state.received.find((i) => i.opcode === 'test');
    assert.equal(sent.raw, `4.test,${big.length + 1}.${big}😀;`, 'guacd reçoit la longueur en points de code');
  } finally {
    await ctx.close();
  }
});

test('fermeture côté guacd : les données restantes sont livrées puis 404', async () => {
  const ctx = await setup();
  try {
    const cookie = await loggedIn(ctx.port);
    const tunnel = await openTunnel(ctx.port, cookie);
    const headers = { cookie, 'guacamole-tunnel-token': tunnel.token };
    const [sock] = ctx.guacd.state.sockets;
    sock.end(encodeInstruction('disconnect'));
    await new Promise((r) => setTimeout(r, 50));
    const last = await request(ctx.port, { path: `/tunnel?read:${tunnel.uuid}:0`, headers });
    assert.equal(last.body, '4.sync,1.1;10.disconnect;0.;');
    const after = await request(ctx.port, { path: `/tunnel?read:${tunnel.uuid}:1`, headers });
    assert.equal(after.status, 404);
  } finally {
    await ctx.close();
  }
});

test('guacd injoignable : erreur 503 compréhensible par le client', async () => {
  const ctx = await setup();
  try {
    const cookie = await loggedIn(ctx.port);
    for (const s of ctx.guacd.state.sockets) s.destroy();
    await new Promise((r) => ctx.guacd.server.close(r));
    const res = await openTunnel(ctx.port, cookie);
    assert.equal(res.status, 503);
    assert.equal(res.headers['guacamole-status-code'], String(0x0207));
  } finally {
    await ctx.gateway.close();
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
    const via = (ip, path = '/__auth/login') => request(ctx.port, { path, headers: { 'x-forwarded-for': ip } });

    assert.equal((await via('8.8.8.8')).status, 403);
    assert.equal((await via('8.8.8.8', '/tunnel?connect')).status, 403);
    assert.equal((await via('198.51.100.9')).status, 200);
    assert.equal((await via('203.0.113.7')).status, 200);
    assert.equal((await request(ctx.port, { path: '/__auth/login' })).status, 200, 'localhost toujours autorisé');
  } finally {
    await ctx.close();
  }
});

test('X-Forwarded-For ignoré si la connexion ne vient pas d\'un proxy de confiance', async () => {
  const ctx = await setup({ IP_RESTRICTION_ENABLED: 'true', TRUSTED_PROXIES: '10.9.9.9' });
  try {
    const res = await request(ctx.port, { path: '/__auth/login', headers: { 'x-forwarded-for': '8.8.8.8' } });
    assert.equal(res.status, 200);
  } finally {
    await ctx.close();
  }
});

test('IPV4_ONLY : client IPv6 relayé par un proxy refusé, y compris sur le tunnel', async () => {
  const ctx = await setup({ TRUSTED_PROXIES: '127.0.0.1' });
  try {
    const v6 = await request(ctx.port, { path: '/__auth/login', headers: { 'x-forwarded-for': '2001:db8::1' } });
    assert.equal(v6.status, 403);
    assert.match(v6.body, /IPv4/);
    const tunnel = await request(ctx.port, { method: 'POST', path: '/tunnel?connect', headers: { 'x-forwarded-for': '2001:db8::1' } });
    assert.equal(tunnel.status, 403);
    const v4 = await request(ctx.port, { path: '/__auth/login', headers: { 'x-forwarded-for': '198.51.100.1' } });
    assert.equal(v4.status, 200);
  } finally {
    await ctx.close();
  }
});

test('IPV4_ONLY=false : un client IPv6 est accepté', async () => {
  const ctx = await setup({ TRUSTED_PROXIES: '127.0.0.1', IPV4_ONLY: 'false' });
  try {
    const v6 = await request(ctx.port, { path: '/__auth/login', headers: { 'x-forwarded-for': '2001:db8::1' } });
    assert.equal(v6.status, 200);
  } finally {
    await ctx.close();
  }
});

test('HTTPS avec HTTP/2 : connexion, page client et tunnel', async () => {
  const os = require('node:os');
  const fs = require('node:fs');
  const path = require('node:path');
  const http2 = require('node:http2');
  const { execFileSync } = require('node:child_process');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'rb-tls-'));
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=localhost',
    '-keyout', path.join(dir, 'key.pem'), '-out', path.join(dir, 'cert.pem')], { stdio: 'ignore' });
  const ctx = await setup({ TLS_MODE: 'custom', TLS_CERT_FILE: path.join(dir, 'cert.pem'), TLS_KEY_FILE: path.join(dir, 'key.pem') });
  const session = http2.connect(`https://127.0.0.1:${ctx.port}`, { rejectUnauthorized: false });
  const h2 = (headers, body) => new Promise((resolve, reject) => {
    const req = session.request(headers);
    const chunks = [];
    let head;
    req.on('response', (h) => (head = h));
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => resolve({ status: head[':status'], headers: head, body: Buffer.concat(chunks).toString() }));
    req.on('error', reject);
    req.end(body);
  });
  try {
    const login = await h2(
      { ':method': 'POST', ':path': '/__auth/login', 'content-type': 'application/x-www-form-urlencoded', origin: `https://127.0.0.1:${ctx.port}` },
      'username=nathan&password=motdepasse-solide&next=%2F'
    );
    assert.equal(login.status, 303, 'origine vérifiée via :authority');
    const cookie = login.headers['set-cookie'][0].split(';')[0];
    assert.match(login.headers['set-cookie'][0], /Secure/);

    const page = await h2({ ':path': '/', cookie });
    assert.equal(page.status, 200);
    assert.match(page.body, /client\.js/);

    const connect = await h2({ ':method': 'POST', ':path': '/tunnel?connect', cookie }, 'width=800&height=600');
    assert.equal(connect.status, 200);
    const read = await h2({ ':path': `/tunnel?read:${connect.body}:0`, cookie, 'guacamole-tunnel-token': connect.headers['guacamole-tunnel-token'] });
    assert.equal(read.body, '4.sync,1.1;0.;');
  } finally {
    session.close();
    await ctx.close();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
