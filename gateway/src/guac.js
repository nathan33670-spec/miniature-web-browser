'use strict';

/**
 * Tunnel HTTP Guacamole (sans WebSocket).
 *
 * Implémente côté serveur le protocole attendu par Guacamole.HTTPTunnel :
 *   POST /tunnel?connect           -> ouvre une session guacd, renvoie l'UUID
 *   GET  /tunnel?read:<uuid>:<n>   -> flux d'instructions (réponse terminée par "0.;")
 *   POST /tunnel?write:<uuid>      -> instructions envoyées par le navigateur
 *
 * Chaque réponse de lecture est volontairement courte : un proxy d'entreprise
 * qui met les réponses en tampon laisse donc quand même passer l'image.
 */

const net = require('node:net');
const crypto = require('node:crypto');
const { EventEmitter } = require('node:events');
const { safeEqual } = require('./auth');

const STATUS = {
  SERVER_ERROR: 0x0200,
  UPSTREAM_TIMEOUT: 0x0202,
  UPSTREAM_ERROR: 0x0203,
  RESOURCE_NOT_FOUND: 0x0204,
  UPSTREAM_NOT_FOUND: 0x0207,
  CLIENT_BAD_REQUEST: 0x0300,
  CLIENT_FORBIDDEN: 0x0303,
  CLIENT_TOO_MANY: 0x031d,
};

const END_OF_RESPONSE = '0.;';
const MAX_PENDING_INSTRUCTION = 32 * 1024 * 1024;

// ---------------------------------------------------------------------------
// Protocole Guacamole : "LONGUEUR.VALEUR,LONGUEUR.VALEUR;" (longueurs en points de code)
// ---------------------------------------------------------------------------

function codepointLength(str) {
  let n = 0;
  for (let i = 0; i < str.length; i++) {
    const c = str.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff) i++;
    n++;
  }
  return n;
}

function encodeInstruction(...elements) {
  return elements.map((e) => `${codepointLength(String(e))}.${e}`).join(',') + ';';
}

/** Index situé `count` points de code après `start`, ou -1 si les données sont incomplètes. */
function skipCodepoints(str, start, count) {
  const fastEnd = start + count;
  if (fastEnd > str.length) return -1;
  if (!/[\ud800-\udbff]/.test(str.slice(start, fastEnd))) return fastEnd;
  let i = start;
  for (let n = 0; n < count; n++) {
    if (i >= str.length) return -1;
    const c = str.charCodeAt(i);
    i += c >= 0xd800 && c <= 0xdbff ? 2 : 1;
  }
  return i > str.length ? -1 : i;
}

class InstructionParser {
  constructor() {
    this.buffer = '';
  }

  /** Ajoute des données et retourne les instructions complètes ({ opcode, args, raw }). */
  push(chunk) {
    const buf = this.buffer + chunk;
    const out = [];
    let start = 0;
    outer: while (start < buf.length) {
      let pos = start;
      const elements = [];
      for (;;) {
        const dot = buf.indexOf('.', pos);
        if (dot === -1) {
          if (buf.length - pos > 10) throw new Error('Instruction Guacamole invalide');
          break outer;
        }
        const lengthText = buf.slice(pos, dot);
        if (!/^\d{1,10}$/.test(lengthText)) throw new Error('Instruction Guacamole invalide');
        const end = skipCodepoints(buf, dot + 1, Number(lengthText));
        if (end === -1 || end >= buf.length) break outer;
        elements.push(buf.slice(dot + 1, end));
        const terminator = buf[end];
        if (terminator === ';') {
          out.push({ opcode: elements[0], args: elements.slice(1), raw: buf.slice(start, end + 1) });
          start = end + 1;
          continue outer;
        }
        if (terminator !== ',') throw new Error('Instruction Guacamole invalide');
        pos = end + 1;
      }
    }
    this.buffer = buf.slice(start);
    if (this.buffer.length > MAX_PENDING_INSTRUCTION) throw new Error('Instruction Guacamole trop longue');
    return out;
  }
}

// ---------------------------------------------------------------------------
// Connexion à guacd (poignée de main)
// ---------------------------------------------------------------------------

/**
 * Ouvre une connexion guacd et réalise la négociation. Résout avec le socket,
 * le parseur et les instructions déjà reçues après "ready".
 */
function connectGuacd({ host, port, protocol, params, size, timezone, timeoutMs = 15000 }) {
  return new Promise((resolve, reject) => {
    const socket = net.connect({ host, port, family: 4 });
    const parser = new InstructionParser();
    socket.setEncoding('utf8');
    socket.setNoDelay(true);

    let step = 'args';
    const timer = setTimeout(() => fail(new Error('Délai dépassé pendant la connexion à guacd')), timeoutMs);

    function fail(err) {
      clearTimeout(timer);
      socket.removeAllListeners('data');
      socket.destroy();
      reject(err);
    }

    socket.on('error', fail);
    socket.on('close', () => fail(new Error('guacd a fermé la connexion pendant la négociation')));
    socket.on('connect', () => socket.write(encodeInstruction('select', protocol)));

    socket.on('data', (chunk) => {
      let instructions;
      try {
        instructions = parser.push(chunk);
      } catch (err) {
        return fail(err);
      }
      for (let i = 0; i < instructions.length; i++) {
        const ins = instructions[i];
        if (ins.opcode === 'error') return fail(new Error(`guacd : ${ins.args[0] || 'erreur'}`));
        if (step === 'args' && ins.opcode === 'args') {
          const values = ins.args.map((name) => (name.startsWith('VERSION_') ? name : params[name] ?? ''));
          socket.write(
            encodeInstruction('size', size.width, size.height, size.dpi) +
              encodeInstruction('audio') +
              encodeInstruction('video') +
              encodeInstruction('image', 'image/png', 'image/jpeg', 'image/webp') +
              (timezone ? encodeInstruction('timezone', timezone) : '') +
              encodeInstruction('connect', ...values)
          );
          step = 'ready';
        } else if (step === 'ready' && ins.opcode === 'ready') {
          clearTimeout(timer);
          socket.removeAllListeners('data');
          socket.removeAllListeners('error');
          socket.removeAllListeners('close');
          return resolve({ socket, parser, initial: instructions.slice(i + 1).map((x) => x.raw) });
        }
      }
    });
  });
}

// ---------------------------------------------------------------------------
// Tunnel : file d'instructions guacd -> navigateur, lue par requêtes HTTP successives
// ---------------------------------------------------------------------------

class GuacTunnel extends EventEmitter {
  constructor({ socket, parser, initial = [], owner, options, logger }) {
    super();
    this.uuid = crypto.randomUUID();
    this.token = crypto.randomBytes(32).toString('base64url');
    this.socket = socket;
    this.parser = parser;
    this.owner = owner;
    this.options = options;
    this.logger = logger;
    this.queue = [...initial];
    this.queueBytes = this.queue.reduce((n, s) => n + s.length, 0);
    this.reader = null;
    this.closed = false;
    this.lastActivity = Date.now();

    socket.on('data', (chunk) => {
      let instructions;
      try {
        instructions = this.parser.push(chunk);
      } catch (err) {
        this.logger.warn(`Tunnel ${this.uuid} : ${err.message}`);
        this.destroy();
        return;
      }
      for (const ins of instructions) {
        this.queue.push(ins.raw);
        this.queueBytes += ins.raw.length;
      }
      if (this.queueBytes > this.options.maxQueueBytes) socket.pause();
      this.flush();
    });
    socket.on('error', () => {});
    socket.on('close', () => this.markClosed());
  }

  touch() {
    this.lastActivity = Date.now();
  }

  markClosed() {
    if (this.closed) return;
    this.closed = true;
    this.flush();
    this.emit('close');
  }

  /** Une nouvelle lecture remplace la précédente (qui est terminée proprement). */
  attachReader(res) {
    this.touch();
    this.endReader();
    res.writeHead(200, {
      'content-type': 'application/octet-stream',
      'cache-control': 'no-cache, no-store',
      pragma: 'no-cache',
      'x-accel-buffering': 'no',
    });
    const reader = { res, bytes: 0, idleTimer: null, maxTimer: null };
    reader.maxTimer = setTimeout(() => this.endReader(reader), this.options.maxResponseMs);
    res.on('close', () => {
      if (this.reader === reader) this.endReader(reader, false);
    });
    this.reader = reader;
    this.flush();
  }

  flush() {
    const reader = this.reader;
    if (!reader) return;
    if (this.queue.length) {
      const data = this.queue.join('');
      this.queue = [];
      this.queueBytes = 0;
      reader.bytes += data.length;
      if (!reader.res.write(data)) {
        this.socket.pause();
        reader.res.once('drain', () => this.socket.resume());
      } else if (this.socket.isPaused()) {
        this.socket.resume();
      }
      clearTimeout(reader.idleTimer);
      // Termine la réponse peu après le dernier envoi : les proxys qui
      // attendent la fin d'une réponse avant de la transmettre restent fluides.
      reader.idleTimer = setTimeout(() => this.endReader(reader), this.options.flushDelayMs);
      if (reader.bytes >= this.options.maxResponseBytes) this.endReader(reader);
    } else if (this.socket.isPaused() && reader.res.writableNeedDrain === false) {
      this.socket.resume();
    }
    if (this.closed && this.reader === reader && !this.queue.length) this.endReader(reader);
  }

  endReader(reader = this.reader, writeMarker = true) {
    if (!reader || this.reader !== reader) return;
    this.reader = null;
    clearTimeout(reader.idleTimer);
    clearTimeout(reader.maxTimer);
    if (writeMarker && !reader.res.writableEnded) reader.res.end(END_OF_RESPONSE);
  }

  write(data) {
    this.touch();
    if (this.closed) return false;
    this.socket.write(data);
    return true;
  }

  destroy() {
    this.socket.destroy();
    this.markClosed();
    this.endReader();
  }
}

// ---------------------------------------------------------------------------
// Gestionnaire HTTP
// ---------------------------------------------------------------------------

function sendStatus(res, httpStatus, code, message) {
  res.writeHead(httpStatus, {
    'content-type': 'text/plain; charset=utf-8',
    'cache-control': 'no-store',
    'guacamole-status-code': String(code),
    // En-tête HTTP : ASCII uniquement.
    'guacamole-error-message': message.normalize('NFD').replace(/[^\x20-\x7e]/g, ''),
  });
  res.end(message);
}

function readBody(req, limit) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > limit) {
        reject(Object.assign(new Error('Corps de requête trop volumineux'), { tooLarge: true }));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

function clampInt(value, min, max, fallback) {
  const n = Number.parseInt(value, 10);
  if (!Number.isFinite(n)) return fallback;
  return Math.min(max, Math.max(min, n));
}

class TunnelManager {
  constructor({ guacd, connection, logger, options = {} }) {
    this.guacd = guacd; // { host, port }
    this.connection = connection; // { protocol, params }
    this.logger = logger;
    this.options = {
      maxTunnels: 4,
      inactivityMs: 30_000,
      flushDelayMs: 40,
      maxResponseMs: 1_000,
      maxResponseBytes: 512 * 1024,
      maxQueueBytes: 8 * 1024 * 1024,
      maxWriteBytes: 4 * 1024 * 1024,
      ...options,
    };
    this.tunnels = new Map();
    this.sweeper = setInterval(() => this.sweep(), 5_000);
    this.sweeper.unref();
  }

  sweep(now = Date.now()) {
    for (const [uuid, tunnel] of this.tunnels) {
      if (now - tunnel.lastActivity > this.options.inactivityMs) {
        this.logger.debug(`Tunnel ${uuid} inactif, fermeture`);
        tunnel.destroy();
        this.tunnels.delete(uuid);
      }
    }
  }

  closeAll() {
    clearInterval(this.sweeper);
    for (const tunnel of this.tunnels.values()) tunnel.destroy();
    this.tunnels.clear();
  }

  /** Point d'entrée : la requête est déjà authentifiée ; `owner` est la session. */
  async handle(req, res, url, owner, ctx) {
    const query = url.search.slice(1);
    if (query === 'connect' && req.method === 'POST') return this.handleConnect(req, res, owner, ctx);

    const match = /^(read|write):([0-9a-f-]{36})(?::\d+)?$/.exec(query);
    if (!match) return sendStatus(res, 400, STATUS.CLIENT_BAD_REQUEST, 'Requete de tunnel invalide');
    const [, action, uuid] = match;

    const tunnel = this.tunnels.get(uuid);
    if (!tunnel) return sendStatus(res, 404, STATUS.RESOURCE_NOT_FOUND, 'Tunnel introuvable');
    const token = req.headers['guacamole-tunnel-token'] || '';
    if (tunnel.owner !== owner || !safeEqual(token, tunnel.token)) {
      return sendStatus(res, 403, STATUS.CLIENT_FORBIDDEN, 'Acces au tunnel refuse');
    }

    if (action === 'read' && req.method === 'GET') {
      if (tunnel.closed && !tunnel.queue.length) {
        this.tunnels.delete(uuid);
        return sendStatus(res, 404, STATUS.RESOURCE_NOT_FOUND, 'Tunnel ferme');
      }
      return tunnel.attachReader(res);
    }

    if (action === 'write' && req.method === 'POST') {
      let body;
      try {
        body = await readBody(req, this.options.maxWriteBytes);
      } catch {
        return sendStatus(res, 413, STATUS.CLIENT_BAD_REQUEST, 'Donnees trop volumineuses');
      }
      if (!tunnel.write(body)) return sendStatus(res, 404, STATUS.RESOURCE_NOT_FOUND, 'Tunnel ferme');
      res.writeHead(200, { 'content-type': 'text/plain', 'cache-control': 'no-store', 'content-length': '0' });
      return res.end();
    }

    return sendStatus(res, 405, STATUS.CLIENT_BAD_REQUEST, 'Methode non autorisee');
  }

  async handleConnect(req, res, owner, ctx) {
    if (this.tunnels.size >= this.options.maxTunnels) this.sweep();
    if (this.tunnels.size >= this.options.maxTunnels) {
      // Libère le tunnel le plus ancien de cette même session (onglet rechargé).
      const oldest = [...this.tunnels.values()].filter((t) => t.owner === owner).sort((a, b) => a.lastActivity - b.lastActivity)[0];
      if (!oldest) return sendStatus(res, 429, STATUS.CLIENT_TOO_MANY, 'Trop de connexions simultanees');
      oldest.destroy();
      this.tunnels.delete(oldest.uuid);
    }

    let form;
    try {
      form = new URLSearchParams(await readBody(req, 4096));
    } catch {
      return sendStatus(res, 413, STATUS.CLIENT_BAD_REQUEST, 'Requete trop volumineuse');
    }
    const size = {
      width: clampInt(form.get('width'), 320, 7680, 1280),
      height: clampInt(form.get('height'), 240, 4320, 720),
      dpi: clampInt(form.get('dpi'), 48, 384, 96),
    };
    const timezone = /^[A-Za-z0-9_+\-/]{1,64}$/.test(form.get('timezone') || '') ? form.get('timezone') : '';

    let session;
    try {
      session = await connectGuacd({ ...this.guacd, ...this.connection, size, timezone });
    } catch (err) {
      this.logger.error(`Connexion au bureau distant impossible : ${err.message}`);
      return sendStatus(res, 503, STATUS.UPSTREAM_NOT_FOUND, 'Navigateur distant indisponible');
    }

    const tunnel = new GuacTunnel({ ...session, owner, options: this.options, logger: this.logger });
    this.tunnels.set(tunnel.uuid, tunnel);
    tunnel.once('close', () => {
      // On garde le tunnel le temps que le navigateur lise les dernières instructions.
      setTimeout(() => {
        if (this.tunnels.get(tunnel.uuid) === tunnel) this.tunnels.delete(tunnel.uuid);
      }, 10_000).unref();
    });
    this.logger.info(`Session d'affichage ouverte (${size.width}x${size.height}) depuis ${ctx.clientIp}`);

    res.writeHead(200, {
      'content-type': 'text/plain; charset=utf-8',
      'cache-control': 'no-store',
      'guacamole-tunnel-token': tunnel.token,
    });
    res.end(tunnel.uuid);
    return tunnel;
  }
}

module.exports = {
  STATUS,
  InstructionParser,
  encodeInstruction,
  codepointLength,
  connectGuacd,
  GuacTunnel,
  TunnelManager,
  END_OF_RESPONSE,
};
