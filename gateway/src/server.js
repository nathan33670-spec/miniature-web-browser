'use strict';

const fs = require('node:fs');
const net = require('node:net');
const http = require('node:http');
const http2 = require('node:http2');

const { AccessControl, IpSet, resolveClientIp, detectDockerGateways, normalizeIp } = require('./ipfilter');
const { verifyPassword, hashPassword, safeEqual, TotpVerifier, SessionStore, LoginLimiter } = require('./auth');
const { PublicIpTracker } = require('./publicip');
const { TunnelManager } = require('./guac');
const { loadAssets, serveAsset } = require('./static');
const { loginPage, messagePage } = require('./pages');

const AUTH_PREFIX = '/__auth/';
const MAX_BODY = 8 * 1024;

function createLogger(level = 'info') {
  const levels = { debug: 10, info: 20, warn: 30, error: 40 };
  const min = levels[level] ?? 20;
  const log = (lvl) => (msg) => {
    if (levels[lvl] >= min) console[lvl === 'debug' ? 'log' : lvl](`${new Date().toISOString()} [${lvl}] ${msg}`);
  };
  return { debug: log('debug'), info: log('info'), warn: log('warn'), error: log('error') };
}

function parseCookies(header) {
  const out = {};
  for (const part of String(header || '').split(';')) {
    const idx = part.indexOf('=');
    if (idx === -1) continue;
    const name = part.slice(0, idx).trim();
    if (name && !(name in out)) out[name] = decodeURIComponent(part.slice(idx + 1).trim());
  }
  return out;
}

function safeNext(value) {
  const next = String(value || '/');
  // Uniquement un chemin relatif à ce site (pas de "//domaine" ni de "/\domaine").
  if (!next.startsWith('/') || next.startsWith('//') || next.startsWith('/\\') || next.startsWith(AUTH_PREFIX)) return '/';
  return next;
}

function readBody(req, limit = MAX_BODY) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > limit) {
        reject(new Error('Corps de requête trop volumineux'));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

const CLIENT_CSP =
  "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; " +
  "connect-src 'self'; media-src 'self' blob:; form-action 'self'; frame-ancestors 'none'; base-uri 'none'";

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function securityHeaders(extra = {}) {
  return {
    'content-type': 'text/html; charset=utf-8',
    'cache-control': 'no-store',
    'x-frame-options': 'DENY',
    'x-content-type-options': 'nosniff',
    'referrer-policy': 'no-referrer',
    'content-security-policy': "default-src 'none'; style-src 'unsafe-inline'; img-src 'self' data:; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
    ...extra,
  };
}

async function createGateway(config, { logger = createLogger(config.logLevel), dockerGateways } = {}) {
  // --- Contrôle d'accès réseau --------------------------------------------
  const gateways = config.access.trustDockerGateway ? dockerGateways ?? detectDockerGateways() : [];
  const access = new AccessControl({
    enabled: config.access.enabled,
    allowlist: config.access.allowlist,
    alwaysAllowed: [...config.access.nasIps, ...gateways],
  });
  const trustedProxies = new IpSet(config.access.trustedProxies);

  let publicIp = null;
  if (config.access.enabled && config.access.allowPublicIp) {
    publicIp = new PublicIpTracker({
      staticIps: config.access.publicIps,
      hostnames: config.access.publicHostnames,
      autodetect: config.access.publicIpAutodetect,
      urls: config.access.publicIpUrls,
      refreshMs: config.access.publicIpRefreshMs,
      ipv4Only: config.access.ipv4Only,
      logger,
      onChange: (ips) => access.setDynamic(ips),
    });
  }

  // --- Authentification ----------------------------------------------------
  let passwordHash = config.auth.passwordHash;
  if (!passwordHash) {
    logger.warn('AUTH_PASSWORD est en clair dans la configuration : préférez AUTH_PASSWORD_HASH.');
    passwordHash = await hashPassword(config.auth.password);
  }
  const totp = config.auth.totpSecret ? new TotpVerifier(config.auth.totpSecret) : null;
  const sessions = new SessionStore(config.session);
  const limiter = new LoginLimiter(config.login);
  const assets = loadAssets();
  const tunnels = new TunnelManager({
    guacd: config.guacd,
    connection: {
      protocol: 'vnc',
      params: {
        hostname: config.desktop.host,
        port: String(config.desktop.port),
        password: config.desktop.password,
        'color-depth': '24',
        'clipboard-encoding': 'UTF-8',
        autoretry: '10',
      },
    },
    logger,
  });
  const tlsEnabled = config.tls.mode !== 'off';

  function context(req) {
    const remote = req.socket.remoteAddress;
    const clientIp = resolveClientIp(remote, req.headers['x-forwarded-for'], trustedProxies);
    const viaProxy = trustedProxies.size > 0 && trustedProxies.has(remote);
    const secure = tlsEnabled || (viaProxy && String(req.headers['x-forwarded-proto'] || '').split(',')[0].trim() === 'https');
    const host = (viaProxy && req.headers['x-forwarded-host']) || req.headers.host || req.headers[':authority'] || '';
    return { clientIp, secure, host };
  }

  function cookieSecure(ctx) {
    if (config.session.cookieSecure === 'auto') return ctx.secure;
    return config.session.cookieSecure === 'true';
  }

  function sessionCookie(token, ctx, maxAgeSec) {
    const parts = [`${config.session.cookieName}=${token}`, 'Path=/', 'HttpOnly', 'SameSite=Strict', `Max-Age=${maxAgeSec}`];
    if (cookieSecure(ctx)) parts.push('Secure');
    return parts.join('; ');
  }

  function getToken(req) {
    return parseCookies(req.headers.cookie)[config.session.cookieName];
  }

  function send(res, status, body, headers = {}) {
    res.writeHead(status, securityHeaders(headers));
    res.end(body);
  }

  async function handleLogin(req, res, ctx, url) {
    if (req.method === 'GET') {
      if (sessions.get(getToken(req), { touch: false })) {
        return send(res, 302, '', { location: safeNext(url.searchParams.get('next')) });
      }
      return send(res, 200, loginPage({ next: safeNext(url.searchParams.get('next')), totp: !!totp }));
    }
    if (req.method !== 'POST') return send(res, 405, messagePage('Méthode non autorisée', ''), { allow: 'GET, POST' });

    // Protection CSRF : le formulaire doit être soumis depuis ce même site.
    const origin = req.headers.origin;
    if (origin && origin !== 'null') {
      let originHost = '';
      try {
        originHost = new URL(origin).host;
      } catch {}
      if (originHost.toLowerCase() !== ctx.host.toLowerCase()) {
        logger.warn(`Connexion refusée (origine ${origin} ≠ ${ctx.host}) depuis ${ctx.clientIp}`);
        return send(res, 403, messagePage('Requête refusée', 'Origine de la requête non reconnue.'));
      }
    }

    let form;
    try {
      form = new URLSearchParams(await readBody(req));
    } catch {
      return send(res, 413, messagePage('Requête refusée', 'Requête trop volumineuse.'));
    }
    const next = safeNext(form.get('next'));
    const username = form.get('username') || '';

    const locked = limiter.lockedUntil(ctx.clientIp);
    if (locked) {
      const minutes = Math.ceil((locked - Date.now()) / 60_000);
      logger.warn(`Connexion bloquée (verrouillage actif) pour ${ctx.clientIp}`);
      return send(res, 429, loginPage({ error: `Trop de tentatives. Réessayez dans ${minutes} min.`, next, totp: !!totp, username }), {
        'retry-after': String(Math.ceil((locked - Date.now()) / 1000)),
      });
    }

    const userOk = safeEqual(username, config.auth.username);
    const passOk = await verifyPassword(form.get('password') || '', passwordHash);
    const totpOk = !totp || (userOk && passOk && totp.verify(form.get('totp')));

    if (!(userOk && passOk && totpOk)) {
      const nowLocked = limiter.recordFailure(ctx.clientIp);
      logger.warn(`Échec de connexion pour "${username}" depuis ${ctx.clientIp}${nowLocked ? ' — IP verrouillée' : ''}`);
      await sleep(config.login.failureDelayMs);
      const error = nowLocked ? 'Trop de tentatives. Accès temporairement bloqué.' : 'Identifiants ou code invalides.';
      return send(res, nowLocked ? 429 : 401, loginPage({ error, next, totp: !!totp, username }));
    }

    limiter.recordSuccess(ctx.clientIp);
    const token = sessions.create({ ip: ctx.clientIp, userAgent: req.headers['user-agent'] || '' });
    logger.info(`Connexion réussie de "${username}" depuis ${ctx.clientIp}`);
    return send(res, 303, '', {
      location: next,
      'set-cookie': sessionCookie(token, ctx, Math.floor(config.session.ttlMs / 1000)),
    });
  }

  async function handleAuthRoute(req, res, ctx, url) {
    switch (url.pathname) {
      case '/__auth/login':
        return handleLogin(req, res, ctx, url);
      case '/__auth/logout':
        sessions.destroy(getToken(req));
        logger.info(`Déconnexion depuis ${ctx.clientIp}`);
        return send(res, 303, '', { location: '/__auth/login', 'set-cookie': sessionCookie('', ctx, 0) });
      case '/__auth/health':
        return send(res, 200, 'ok', { 'content-type': 'text/plain; charset=utf-8' });
      default:
        return send(res, 404, messagePage('Introuvable', ''));
    }
  }

  /** IPV4_ONLY : toute adresse cliente IPv6 (directe ou relayée) est refusée. */
  function familyAllowed(ip) {
    return !config.access.ipv4Only || net.isIPv4(ip);
  }

  async function onRequest(req, res) {
    const ctx = context(req);
    if (!familyAllowed(ctx.clientIp)) {
      logger.warn(`Accès refusé pour ${ctx.clientIp} (IPv6 désactivé) : ${req.method} ${req.url}`);
      return send(res, 403, messagePage('Accès refusé', 'Seules les connexions IPv4 sont acceptées.'));
    }
    const reason = access.check(ctx.clientIp);
    if (!reason) {
      logger.warn(`Accès refusé pour ${ctx.clientIp} (hors liste blanche) : ${req.method} ${req.url}`);
      return send(res, 403, messagePage('Accès refusé', 'Votre adresse IP n\'est pas autorisée.'));
    }

    let url;
    try {
      url = new URL(req.url, 'http://gateway');
    } catch {
      return send(res, 400, messagePage('Requête invalide', ''));
    }

    if (url.pathname.startsWith(AUTH_PREFIX)) return handleAuthRoute(req, res, ctx, url);

    const session = sessions.get(getToken(req));
    if (!session) {
      const wantsHtml = req.method === 'GET' && String(req.headers.accept || '').includes('text/html');
      if (wantsHtml) {
        return send(res, 302, '', { location: `/__auth/login?next=${encodeURIComponent(safeNext(req.url))}` });
      }
      return send(res, 401, 'Authentification requise', { 'content-type': 'text/plain; charset=utf-8' });
    }

    // Tunnel d'affichage Guacamole (HTTP uniquement, aucun WebSocket).
    if (url.pathname === '/tunnel') {
      const tunnel = await tunnels.handle(req, res, url, session, ctx);
      if (tunnel) sessions.attachSocket(session, tunnel);
      return;
    }

    const asset = (req.method === 'GET' || req.method === 'HEAD') && assets.get(url.pathname);
    if (asset) {
      return serveAsset(req, res, asset, url.pathname === '/' ? { 'content-security-policy': CLIENT_CSP, 'x-frame-options': 'DENY', 'referrer-policy': 'no-referrer' } : {});
    }
    return send(res, 404, messagePage('Introuvable', ''));
  }

  // Aucun WebSocket n'est utilisé : toute demande d'upgrade est refusée.
  function onUpgrade(req, socket) {
    socket.on('error', () => {});
    socket.end('HTTP/1.1 404 Not Found\r\nconnection: close\r\ncontent-length: 0\r\n\r\n');
    socket.destroy();
  }

  const handler = (req, res) =>
    onRequest(req, res).catch((err) => {
      logger.error(`Erreur interne : ${err.stack || err.message}`);
      if (!res.headersSent) send(res, 500, messagePage('Erreur interne', ''));
      else res.destroy();
    });

  const server = tlsEnabled
    ? // HTTP/2 quand le navigateur (ou le proxy) le permet : plus de limite de
      // 6 connexions, le tunnel peut garder davantage de requêtes en vol.
      http2.createSecureServer(
        { cert: fs.readFileSync(config.tls.certFile), key: fs.readFileSync(config.tls.keyFile), allowHTTP1: true },
        handler
      )
    : http.createServer(handler);
  server.on('upgrade', onUpgrade);
  // Coupe immédiatement les connexions IPv6 directes, avant même la négociation TLS.
  server.on('connection', (socket) => {
    if (config.access.ipv4Only && !net.isIPv4(normalizeIp(socket.remoteAddress))) socket.destroy();
  });
  server.on('clientError', (err, socket) => socket.destroy());
  const h2Sessions = new Set();
  server.on('session', (session) => {
    h2Sessions.add(session);
    session.once('close', () => h2Sessions.delete(session));
  });
  // Pas de limite globale sur la durée d'une requête (téléchargements longs) ;
  // les en-têtes doivent cependant arriver rapidement.
  server.requestTimeout = 0;
  server.headersTimeout = 30_000;

  const sweeper = setInterval(() => {
    sessions.sweep();
    limiter.sweep();
  }, 60_000);
  sweeper.unref();

  return {
    server,
    access,
    sessions,
    limiter,
    tunnels,
    publicIp,
    gateways,
    async listen(port = config.listen.port, host = config.listen.host) {
      if (publicIp) publicIp.start();
      await new Promise((resolve, reject) => {
        server.once('error', reject);
        server.listen(port, host, resolve);
      });
      return server.address();
    },
    async close() {
      clearInterval(sweeper);
      tunnels.closeAll();
      if (publicIp) publicIp.stop();
      for (const key of [...sessions.sessions.keys()]) sessions.destroyByKey(key);
      server.closeAllConnections?.();
      for (const session of h2Sessions) session.destroy();
      await new Promise((resolve) => server.close(resolve));
    },
  };
}

module.exports = { createGateway, createLogger, safeNext, parseCookies };
