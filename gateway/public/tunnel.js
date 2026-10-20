// Tunnel HTTP « pipeliné » pour Guacamole : plusieurs lectures et écritures en
// vol simultanément, numérotées et remises dans l'ordre. Conçu pour les proxys
// d'entreprise lents ou qui mettent les réponses en tampon (aucun WebSocket).
import Guacamole from './guacamole-common.js';

const State = Guacamole.Tunnel.State;
const Code = Guacamole.Status.Code;
const END_MARKER = '0.;';

class TunnelError extends Error {
  constructor(status) {
    super(status.message || `Erreur ${status.code}`);
    this.status = status;
  }
}

async function statusFromResponse(res) {
  const code = Number.parseInt(res.headers.get('Guacamole-Status-Code'), 10);
  if (code) return new Guacamole.Status(code, res.headers.get('Guacamole-Error-Message') || '');
  return new Guacamole.Status(Code.fromHTTPCode(res.status), res.statusText);
}

function encode(elements) {
  return elements.map((e) => {
    const s = String(e);
    return `${s.length}.${s}`;
  }).join(',') + ';';
}

/**
 * @param {string} url       URL du tunnel (ex. "/tunnel")
 * @param {object} options   { reads: lectures simultanées, writes: écritures simultanées }
 */
export function PipelinedTunnel(url, { reads = 3, writes = 2 } = {}) {
  Guacamole.Tunnel.call(this);
  const tunnel = this;

  let token = null;
  let abort = new AbortController();

  // Lectures
  let nextReadSeq = 0;
  let nextProcessSeq = 0;
  let readsInFlight = 0;
  const completed = new Map();
  const parser = new Guacamole.Parser();
  parser.oninstruction = (opcode, args) => {
    if (tunnel.oninstruction) tunnel.oninstruction(opcode, args);
  };

  // Écritures
  let nextWriteSeq = 0;
  let writesInFlight = 0;
  let outgoing = '';

  // Minuteries de stabilité
  let receiveTimer = null;
  let unstableTimer = null;

  function resetTimers() {
    clearTimeout(receiveTimer);
    clearTimeout(unstableTimer);
    if (tunnel.state === State.UNSTABLE) tunnel.setState(State.OPEN);
    receiveTimer = setTimeout(() => close(new Guacamole.Status(Code.UPSTREAM_TIMEOUT, 'Server timeout.')), tunnel.receiveTimeout);
    unstableTimer = setTimeout(() => tunnel.setState(State.UNSTABLE), tunnel.unstableThreshold);
  }

  function close(status) {
    clearTimeout(receiveTimer);
    clearTimeout(unstableTimer);
    if (tunnel.state === State.CLOSED) return;
    abort.abort();
    if (status.code !== Code.SUCCESS && tunnel.onerror) {
      // RESOURCE_NOT_FOUND une fois connecté = fin normale du flux.
      if (tunnel.state === State.CONNECTING || status.code !== Code.RESOURCE_NOT_FOUND) tunnel.onerror(status);
    }
    tunnel.setState(State.CLOSED);
  }

  function fail(err) {
    if (abort.signal.aborted) return;
    close(err instanceof TunnelError ? err.status : new Guacamole.Status(Code.UPSTREAM_NOT_FOUND, String(err && err.message || err)));
  }

  function headers(extra = {}) {
    return { 'Guacamole-Tunnel-Token': token, ...extra };
  }

  // --- Lectures -----------------------------------------------------------------

  function startRead() {
    const seq = nextReadSeq++;
    readsInFlight++;
    fetch(`${url}?read:${tunnel.uuid}:${seq}`, {
      headers: headers(),
      cache: 'no-store',
      credentials: 'same-origin',
      signal: abort.signal,
    })
      .then(async (res) => {
        if (res.status !== 200) throw new TunnelError(await statusFromResponse(res));
        return res.text();
      })
      .then((text) => {
        readsInFlight--;
        completed.set(seq, text);
        processCompleted();
        fillReads();
      })
      .catch(fail);
  }

  function fillReads() {
    while (tunnel.isConnected() && readsInFlight < reads) startRead();
  }

  function processCompleted() {
    while (completed.has(nextProcessSeq) && tunnel.isConnected()) {
      const text = completed.get(nextProcessSeq);
      completed.delete(nextProcessSeq);
      nextProcessSeq++;
      resetTimers();
      if (!text.endsWith(END_MARKER)) {
        close(new Guacamole.Status(Code.SERVER_ERROR, 'Réponse du tunnel tronquée.'));
        return;
      }
      try {
        parser.receive(text.slice(0, -END_MARKER.length));
      } catch (err) {
        close(new Guacamole.Status(Code.SERVER_ERROR, err.message));
        return;
      }
    }
  }

  // --- Écritures ----------------------------------------------------------------

  function flushWrites() {
    if (!outgoing || writesInFlight >= writes || !tunnel.isConnected()) return;
    const body = outgoing;
    outgoing = '';
    const seq = nextWriteSeq++;
    writesInFlight++;
    fetch(`${url}?write:${tunnel.uuid}:${seq}`, {
      method: 'POST',
      headers: headers({ 'Content-Type': 'application/octet-stream' }),
      body,
      cache: 'no-store',
      credentials: 'same-origin',
      signal: abort.signal,
    })
      .then(async (res) => {
        if (res.status !== 200) throw new TunnelError(await statusFromResponse(res));
        writesInFlight--;
        flushWrites();
      })
      .catch(fail);
  }

  this.sendMessage = function sendMessage(...elements) {
    if (!tunnel.isConnected() || elements.length === 0) return;
    outgoing += encode(elements);
    // Regroupe les messages émis dans la même boucle d'événements (mouvements de souris…).
    queueMicrotask(flushWrites);
  };

  // --- Connexion --------------------------------------------------------------

  this.connect = function connect(data) {
    abort = new AbortController();
    resetTimers();
    tunnel.setState(State.CONNECTING);
    fetch(`${url}?connect`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8' },
      body: data,
      cache: 'no-store',
      credentials: 'same-origin',
      signal: abort.signal,
    })
      .then(async (res) => {
        if (res.status !== 200) throw new TunnelError(await statusFromResponse(res));
        token = res.headers.get('Guacamole-Tunnel-Token');
        const uuid = await res.text();
        if (!token) throw new TunnelError(new Guacamole.Status(Code.UPSTREAM_NOT_FOUND, 'Jeton de tunnel absent.'));
        resetTimers();
        tunnel.setUUID(uuid);
        tunnel.setState(State.OPEN);
        fillReads();
      })
      .catch(fail);
  };

  /** État interne (diagnostic). */
  this.debugState = () => ({
    state: tunnel.state,
    nextReadSeq,
    nextProcessSeq,
    readsInFlight,
    waiting: [...completed.keys()],
    nextWriteSeq,
    writesInFlight,
    outgoing: outgoing.length,
  });

  this.disconnect = function disconnect() {
    close(new Guacamole.Status(Code.SUCCESS, 'Manually closed.'));
  };
}

PipelinedTunnel.prototype = new Guacamole.Tunnel();
