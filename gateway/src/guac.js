'use strict';

/**
 * Tunnel HTTP Guacamole « pipeliné » (sans WebSocket).
 *
 *   POST /tunnel?connect              -> ouvre une session guacd, renvoie l'UUID
 *   GET  /tunnel?read:<uuid>:<n>      -> lot d'instructions n (réponse terminée par "0.;")
 *   POST /tunnel?write:<uuid>:<n>     -> lot d'instructions n envoyé par le navigateur
 *
 * Le navigateur garde plusieurs lectures et écritures en vol en même temps ; le
 * serveur les traite strictement dans l'ordre de leur numéro. Chaque réponse
 * est courte (fin d'image ou quelques dizaines de ms), complète et compressée :
 * un proxy d'entreprise qui met les réponses en tampon ou ajoute de la latence
 * ne bloque donc plus le flux.
 */

const net = require('node:net');
const zlib = require('node:zlib');
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
const SURROGATE = /[\ud800-\udbff]/;

// ---------------------------------------------------------------------------
// Protocole Guacamole : "LONGUEUR.VALEUR,LONGUEUR.VALEUR;"
// guacd compte les longueurs en points de code Unicode, le client JavaScript en
// unités UTF-16 : la passerelle convertit dans les deux sens si nécessaire.
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

/** Encodage pour guacd (points de code). */
function encodeInstruction(...elements) {
  return elements.map((e) => `${codepointLength(String(e))}.${e}`).join(',') + ';';
}

/** Encodage pour le navigateur (unités UTF-16). */
function encodeInstructionUtf16(...elements) {
  return elements.map((e) => `${String(e).length}.${e}`).join(',') + ';';
}

/** Index situé `count` points de code après `start`, ou -1 si les données sont incomplètes. */
function skipCodepoints(str, start, count) {
  const fastEnd = start + count;
  if (fastEnd > str.length) return -1;
  if (!SURROGATE.test(str.slice(start, fastEnd))) return fastEnd;
  let i = start;
  for (let n = 0; n < count; n++) {
    if (i >= str.length) return -1;
    const c = str.charCodeAt(i);
    i += c >= 0xd800 && c <= 0xdbff ? 2 : 1;
  }
  return i > str.length ? -1 : i;
}

function skipUtf16(str, start, count) {
  const end = start + count;
  return end > str.length ? -1 : end;
}

class InstructionParser {
  /** @param {{ units?: 'codepoint' | 'utf16' }} options */
  constructor({ units = 'codepoint' } = {}) {
    this.buffer = '';
    this.skip = units === 'utf16' ? skipUtf16 : skipCodepoints;
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
        const end = this.skip(buf, dot + 1, Number(lengthText));
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

/** Instruction guacd -> texte pour le navigateur. */
function toBrowser(ins) {
  return SURROGATE.test(ins.raw) ? encodeInstructionUtf16(ins.opcode, ...ins.args) : ins.raw;
}

/** Instruction du navigateur -> texte pour guacd. */
function toGuacd(ins) {
  return SURROGATE.test(ins.raw) ? encodeInstruction(ins.opcode, ...ins.args) : ins.raw;
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
              encodeInstruction('image', 'image/webp', 'image/jpeg', 'image/png') +
              (timezone ? encodeInstruction('timezone', timezone) : '') +
              encodeInstruction('connect', ...values)
          );
          step = 'ready';
        } else if (step === 'ready' && ins.opcode === 'ready') {
          clearTimeout(timer);
          socket.removeAllListeners('data');
          socket.removeAllListeners('error');
          socket.removeAllListeners('close');
          return resolve({ socket, parser, initial: instructions.slice(i + 1) });
        }
      }
    });
  });
}

// ---------------------------------------------------------------------------
// Tunnel
// ---------------------------------------------------------------------------

const RESPONSE_HEADERS = {
  'content-type': 'application/octet-stream',
  'cache-control': 'no-cache, no-store, no-transform',
  pragma: 'no-cache',
  'x-accel-buffering': 'no',
};

class GuacTunnel extends EventEmitter {
  constructor({ socket, parser, initial = [], owner, options, logger }) {
    super();
    this.uuid = crypto.randomUUID();
    this.token = crypto.randomBytes(32).toString('base64url');
    this.socket = socket;
    this.parser = parser;
    this.clientParser = new InstructionParser({ units: 'utf16' });
    this.owner = owner;
    this.options = options;
    this.logger = logger;
    this.closed = false;
    this.lastActivity = Date.now();

    // guacd -> navigateur
    this.queue = [];
    this.queueBytes = 0;
    this.queueHasSync = false;
    this.enqueue(initial);

    // Lectures en attente, servies strictement dans l'ordre
    this.nextReadSeq = 0;
    this.pendingReads = new Map();
    this.reader = null;
    this.readGapTimer = null;

    // Écritures, appliquées strictement dans l'ordre
    this.nextWriteSeq = 0;
    this.pendingWrites = new Map();
    this.writeGapTimer = null;

    socket.on('data', (chunk) => {
      let instructions;
      try {
        instructions = this.parser.push(chunk);
      } catch (err) {
        this.logger.warn(`Tunnel ${this.uuid} : ${err.message}`);
        this.destroy();
        return;
      }
      this.enqueue(instructions);
      // Petite file : si le navigateur ne suit pas, guacd est freiné et regroupe
      // les mises à jour au lieu d'accumuler du retard.
      if (this.queueBytes > this.options.maxQueueBytes) socket.pause();
      this.pump();
    });
    socket.on('error', () => {});
    socket.on('close', () => this.markClosed());
  }

  enqueue(instructions) {
    for (const ins of instructions) {
      const text = toBrowser(ins);
      this.queue.push(text);
      this.queueBytes += text.length;
      if (ins.opcode === 'sync') this.queueHasSync = true;
    }
  }

  touch() {
    this.lastActivity = Date.now();
  }

  markClosed() {
    if (this.closed) return;
    this.closed = true;
    this.pump();
    this.emit('close');
  }

  // --- Lectures ---------------------------------------------------------------

  addReader(seq, res, gzip) {
    this.touch();
    if (seq < this.nextReadSeq || this.pendingReads.has(seq) || this.pendingReads.size >= this.options.maxPendingReads) {
      return false;
    }
    const reader = { seq, res, gzip, chunks: [], bytes: 0, timers: [], done: false };
    res.on('close', () => {
      if (reader.done) return;
      reader.done = true;
      reader.timers.forEach(clearTimeout);
      this.pendingReads.delete(seq);
      if (this.reader === reader) {
        this.reader = null;
        this.pump();
      }
    });
    this.pendingReads.set(seq, reader);
    this.pump();
    return true;
  }

  /** Active la prochaine lecture dans l'ordre et lui transmet les données en attente. */
  pump() {
    if (!this.reader) {
      const next = this.pendingReads.get(this.nextReadSeq);
      if (!next) {
        // Une requête intermédiaire n'est pas (encore) arrivée : on patiente, puis on la saute.
        if (this.pendingReads.size && !this.readGapTimer) {
          this.readGapTimer = setTimeout(() => {
            this.readGapTimer = null;
            if (!this.reader && this.pendingReads.size && !this.pendingReads.has(this.nextReadSeq)) {
              this.nextReadSeq = Math.min(...this.pendingReads.keys());
              this.pump();
            }
          }, this.options.sequenceGapMs);
        }
        return;
      }
      clearTimeout(this.readGapTimer);
      this.readGapTimer = null;
      this.pendingReads.delete(next.seq);
      this.nextReadSeq++;
      this.reader = next;
      // Long polling : sans données, la réponse se termine tout de même régulièrement.
      next.timers.push(setTimeout(() => this.finishReader(next), this.options.longPollMs));
    }

    const reader = this.reader;
    if (this.queue.length) {
      for (const text of this.queue) reader.chunks.push(text);
      reader.bytes += this.queueBytes;
      const hadSync = this.queueHasSync;
      this.queue = [];
      this.queueBytes = 0;
      this.queueHasSync = false;
      if (this.socket.isPaused()) this.socket.resume();

      if (hadSync || reader.bytes >= this.options.maxResponseBytes) {
        // Fin d'image (ou lot plein) : on envoie tout de suite.
        reader.timers.push(setImmediate(() => this.finishReader(reader)));
      } else {
        if (!reader.firstDataAt) {
          reader.firstDataAt = Date.now();
          reader.timers.push(setTimeout(() => this.finishReader(reader), this.options.maxBatchMs));
        }
        clearTimeout(reader.idleTimer);
        reader.idleTimer = setTimeout(() => this.finishReader(reader), this.options.flushDelayMs);
        reader.timers.push(reader.idleTimer);
      }
    } else if (this.closed) {
      this.finishReader(reader);
    }
  }

  finishReader(reader) {
    if (reader.done) return;
    reader.done = true;
    reader.timers.forEach((t) => {
      clearTimeout(t);
      clearImmediate(t);
    });
    if (this.reader === reader) this.reader = null;

    const body = reader.chunks.join('') + END_OF_RESPONSE;
    const res = reader.res;
    const send = (payload, extra = {}) => {
      if (res.destroyed || res.writableEnded) return;
      res.writeHead(200, { ...RESPONSE_HEADERS, ...extra, 'content-length': String(payload.length) });
      res.end(payload);
    };
    if (reader.gzip && body.length > this.options.gzipMinBytes) {
      zlib.gzip(body, { level: this.options.gzipLevel }, (err, compressed) => {
        if (err) send(Buffer.from(body));
        else send(compressed, { 'content-encoding': 'gzip' });
      });
    } else {
      send(Buffer.from(body));
    }

    // Tunnel fermé : les lectures restantes reçoivent une réponse vide.
    if (this.closed && !this.queue.length) {
      const remaining = [...this.pendingReads.values()];
      this.pendingReads.clear();
      remaining.forEach((pending) => this.finishReader(pending));
      return;
    }
    this.pump();
  }

  // --- Écritures ----------------------------------------------------------------

  addWrite(seq, body) {
    this.touch();
    if (this.closed) return false;
    if (seq === null) return this.applyWrite(body);
    if (seq < this.nextWriteSeq || this.pendingWrites.has(seq)) return true;
    if (this.pendingWrites.size >= this.options.maxPendingWrites) return false;
    this.pendingWrites.set(seq, body);
    this.drainWrites();
    return !this.closed;
  }

  drainWrites() {
    while (this.pendingWrites.has(this.nextWriteSeq)) {
      const body = this.pendingWrites.get(this.nextWriteSeq);
      this.pendingWrites.delete(this.nextWriteSeq);
      this.nextWriteSeq++;
      if (!this.applyWrite(body)) return;
    }
    clearTimeout(this.writeGapTimer);
    this.writeGapTimer = null;
    if (this.pendingWrites.size) {
      this.writeGapTimer = setTimeout(() => {
        this.writeGapTimer = null;
        if (!this.pendingWrites.size) return;
        this.logger.warn(`Tunnel ${this.uuid} : écriture ${this.nextWriteSeq} perdue, reprise à la suivante`);
        this.nextWriteSeq = Math.min(...this.pendingWrites.keys());
        this.drainWrites();
      }, this.options.sequenceGapMs);
    }
  }

  applyWrite(body) {
    let instructions;
    try {
      instructions = this.clientParser.push(body);
    } catch (err) {
      this.logger.warn(`Tunnel ${this.uuid} : ${err.message}`);
      this.destroy();
      return false;
    }
    let out = '';
    for (const ins of instructions) {
      if (ins.opcode !== '') out += toGuacd(ins); // instructions internes au tunnel ignorées
    }
    if (out) this.socket.write(out);
    return true;
  }

  destroy() {
    this.socket.destroy();
    this.markClosed();
    if (this.reader) this.finishReader(this.reader);
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

const DEFAULT_OPTIONS = {
  maxTunnels: 4,
  inactivityMs: 30_000,
  flushDelayMs: 8, // regroupe les instructions arrivant presque ensemble
  maxBatchMs: 40, // délai maximal avant d'envoyer des données sans fin d'image
  longPollMs: 10_000, // durée maximale d'une lecture sans données
  maxResponseBytes: 512 * 1024,
  maxQueueBytes: 768 * 1024,
  maxPendingReads: 8,
  maxPendingWrites: 16,
  sequenceGapMs: 3_000,
  maxWriteBytes: 4 * 1024 * 1024,
  gzipMinBytes: 1024,
  gzipLevel: 1,
};

class TunnelManager {
  constructor({ guacd, connection, logger, options = {} }) {
    this.guacd = guacd; // { host, port }
    this.connection = connection; // { protocol, params }
    this.logger = logger;
    this.options = { ...DEFAULT_OPTIONS, ...options };
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

    const match = /^(read|write):([0-9a-f-]{36})(?::(\d{1,15}))?$/.exec(query);
    if (!match) return sendStatus(res, 400, STATUS.CLIENT_BAD_REQUEST, 'Requete de tunnel invalide');
    const [, action, uuid, seqText] = match;
    const seq = seqText === undefined ? null : Number(seqText);

    const tunnel = this.tunnels.get(uuid);
    if (!tunnel) return sendStatus(res, 404, STATUS.RESOURCE_NOT_FOUND, 'Tunnel introuvable');
    const token = req.headers['guacamole-tunnel-token'] || '';
    if (tunnel.owner !== owner || !safeEqual(token, tunnel.token)) {
      return sendStatus(res, 403, STATUS.CLIENT_FORBIDDEN, 'Acces au tunnel refuse');
    }

    if (action === 'read' && req.method === 'GET') {
      if (seq === null) return sendStatus(res, 400, STATUS.CLIENT_BAD_REQUEST, 'Numero de lecture manquant');
      if (tunnel.closed && !tunnel.queue.length && !tunnel.reader) {
        this.tunnels.delete(uuid);
        return sendStatus(res, 404, STATUS.RESOURCE_NOT_FOUND, 'Tunnel ferme');
      }
      const gzip = /\bgzip\b/.test(String(req.headers['accept-encoding'] || ''));
      if (!tunnel.addReader(seq, res, gzip)) return sendStatus(res, 400, STATUS.CLIENT_BAD_REQUEST, 'Lecture hors sequence');
      return undefined;
    }

    if (action === 'write' && req.method === 'POST') {
      let body;
      try {
        body = await readBody(req, this.options.maxWriteBytes);
      } catch {
        return sendStatus(res, 413, STATUS.CLIENT_BAD_REQUEST, 'Donnees trop volumineuses');
      }
      if (!tunnel.addWrite(seq, body)) return sendStatus(res, 404, STATUS.RESOURCE_NOT_FOUND, 'Tunnel ferme');
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
  encodeInstructionUtf16,
  codepointLength,
  connectGuacd,
  GuacTunnel,
  TunnelManager,
  END_OF_RESPONSE,
};
