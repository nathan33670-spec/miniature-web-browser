'use strict';

const fs = require('node:fs');
const http = require('node:http');
const https = require('node:https');

const { AccessControl, IpSet, resolveClientIp, detectDockerGateways } = require('./ipfilter');
const { verifyPassword, hashPassword, safeEqual, TotpVerifier, SessionStore, LoginLimiter } = require('./auth');
const { PublicIpTracker } = require('./publicip');
const { Proxy } = require('./proxy');
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
  const proxy = new Proxy({ ...config.upstream, cookieName: config.session.cookieName });
  const tlsEnabled = config.tls.mode !== 'off';

  function context(req) {
    const remote = req.socket.remoteAddress;
    const clientIp = resolveClientIp(remote, req.headers['x-forwarded-for'], trustedProxies);
    const viaProxy = trustedProxies.size > 0 && trustedProxies.has(remote);
    const secure = tlsEnabled || (viaProxy && String(req.headers['x-forwarded-proto'] || '').split(',')[0].trim() === 'https');
    const host = (viaProxy && req.headers['x-forwarded-host']) || req.headers.host || '';
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

  async function onRequest(req, res) {
    const ctx = context(req);
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

    if (!sessions.get(getToken(req))) {
      const wantsHtml = req.method === 'GET' && String(req.headers.accept || '').includes('text/html');
      if (wantsHtml) {
        return send(res, 302, '', { location: `/__auth/login?next=${encodeURIComponent(safeNext(req.url))}` });
      }
      return send(res, 401, 'Authentification requise', { 'content-type': 'text/plain; charset=utf-8' });
    }

    proxy.web(req, res, ctx, (err) => {
      logger.error(`Erreur vers le navigateur (${config.upstream.url}) : ${err.message}`);
      if (!res.headersSent) {
        send(res, 502, messagePage('Navigateur indisponible', 'Le navigateur démarre ou est arrêté. Réessayez dans quelques secondes.'), {
          refresh: '5',
        });
      } else {
        res.destroy();
      }
    });
  }

  function onUpgrade(req, socket, head) {
    socket.on('error', () => {});
    const reject = (status, text) => {
      socket.end(`HTTP/1.1 ${status} ${text}\r\nconnection: close\r\ncontent-length: 0\r\n\r\n`);
      socket.destroy();
    };
    const ctx = context(req);
    if (!access.check(ctx.clientIp)) {
      logger.warn(`WebSocket refusé pour ${ctx.clientIp} (hors liste blanche)`);
      return reject(403, 'Forbidden');
    }
    const session = sessions.get(getToken(req));
    if (!session) return reject(401, 'Unauthorized');
    proxy.ws(req, socket, head, ctx, () => sessions.attachSocket(session, socket));
  }

  const handler = (req, res) =>
    onRequest(req, res).catch((err) => {
      logger.error(`Erreur interne : ${err.stack || err.message}`);
      if (!res.headersSent) send(res, 500, messagePage('Erreur interne', ''));
      else res.destroy();
    });

  const server = tlsEnabled
    ? https.createServer({ cert: fs.readFileSync(config.tls.certFile), key: fs.readFileSync(config.tls.keyFile) }, handler)
    : http.createServer(handler);
  server.on('upgrade', onUpgrade);
  server.on('clientError', (err, socket) => socket.destroy());
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
      if (publicIp) publicIp.stop();
      for (const key of [...sessions.sessions.keys()]) sessions.destroyByKey(key);
      server.closeAllConnections?.();
      await new Promise((resolve) => server.close(resolve));
    },
  };
}

module.exports = { createGateway, createLogger, safeNext, parseCookies };
