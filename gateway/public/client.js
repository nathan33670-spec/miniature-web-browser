// Client d'affichage du navigateur distant (Guacamole, tunnel HTTP uniquement).
import Guacamole from './guacamole-common.js';
import { PipelinedTunnel } from './tunnel.js';

const STATE = Guacamole.Client.State;
const STATUS = Guacamole.Status.Code;

const container = document.getElementById('display');
const overlay = document.getElementById('overlay');
const statusText = document.getElementById('status');
const spinner = document.getElementById('spinner');
const reconnectButton = document.getElementById('reconnect');
const toolbar = document.getElementById('toolbar');
const menuButton = document.getElementById('menu-button');
const menu = document.getElementById('menu');
const pasteDialog = document.getElementById('paste-dialog');
const pasteText = document.getElementById('paste-text');

let client = null;
let retryTimer = null;
let retryDelay = 1000;
let lastClipboard = '';
let uiCapturesKeyboard = false;

// ---------------------------------------------------------------------------
// Statut
// ---------------------------------------------------------------------------

function showStatus(message, { busy = true, canRetry = false } = {}) {
  statusText.textContent = message;
  spinner.hidden = !busy;
  reconnectButton.hidden = !canRetry;
  overlay.hidden = false;
}

function hideStatus() {
  overlay.hidden = true;
}

function scheduleReconnect(message) {
  clearTimeout(retryTimer);
  showStatus(`${message} Nouvelle tentative dans ${Math.round(retryDelay / 1000)} s…`, { busy: false, canRetry: true });
  retryTimer = setTimeout(connect, retryDelay);
  retryDelay = Math.min(retryDelay * 2, 30000);
}

// ---------------------------------------------------------------------------
// Taille de l'écran
// ---------------------------------------------------------------------------

// Qualité d'affichage : une résolution distante plus petite (agrandie ensuite
// dans la page) réduit fortement le volume d'images à transmettre.
const QUALITY = { haute: 1, moyenne: 0.8, basse: 0.6 };
function loadQuality() {
  try {
    const q = localStorage.getItem('rb-quality');
    if (q in QUALITY) return q;
  } catch {}
  return 'haute';
}
let quality = loadQuality();

function viewportSize() {
  const f = QUALITY[quality];
  return {
    width: Math.max(320, Math.round(window.innerWidth * f)),
    height: Math.max(240, Math.round(window.innerHeight * f)),
  };
}

function updateQualityMenu() {
  for (const el of menu.querySelectorAll('[data-quality]')) {
    el.setAttribute('aria-checked', String(el.dataset.quality === quality));
  }
}

function rescale() {
  if (!client) return;
  const display = client.getDisplay();
  const width = display.getWidth();
  const height = display.getHeight();
  if (!width || !height) return;
  display.scale(Math.min(window.innerWidth / width, window.innerHeight / height));
}

let resizeTimer = null;
window.addEventListener('resize', () => {
  clearTimeout(resizeTimer);
  resizeTimer = setTimeout(() => {
    if (client) {
      const { width, height } = viewportSize();
      client.sendSize(width, height);
    }
    rescale();
  }, 300);
});

// ---------------------------------------------------------------------------
// Presse-papiers
// ---------------------------------------------------------------------------

function sendClipboard(text) {
  if (!client || !text) return;
  const writer = new Guacamole.StringWriter(client.createClipboardStream('text/plain'));
  writer.sendText(text);
  writer.sendEnd();
  lastClipboard = text;
}

// Presse-papiers local -> distant quand la page reprend le focus.
async function syncLocalClipboard() {
  if (!navigator.clipboard || !navigator.clipboard.readText) return;
  try {
    const text = await navigator.clipboard.readText();
    if (text && text !== lastClipboard) sendClipboard(text);
  } catch {
    // Permission refusée ou contexte non sécurisé : le menu « Envoyer du texte » reste disponible.
  }
}
window.addEventListener('focus', syncLocalClipboard);

// ---------------------------------------------------------------------------
// Connexion
// ---------------------------------------------------------------------------

// Nombre de requêtes simultanées : en HTTP/1.1 le navigateur limite à 6
// connexions par site ; en HTTP/2 (ou HTTP/3) on peut en garder davantage.
function tunnelConcurrency() {
  const params = new URLSearchParams(window.location.search);
  const nav = performance.getEntriesByType('navigation')[0];
  const multiplexed = /^h[23]/.test((nav && nav.nextHopProtocol) || '');
  const pick = (name, fallback, max) => Math.min(max, Math.max(1, Number(params.get(name)) || fallback));
  return {
    reads: pick('reads', multiplexed ? 6 : 3, 8),
    writes: pick('writes', multiplexed ? 3 : 2, 4),
  };
}

function connect() {
  clearTimeout(retryTimer);
  if (client) {
    client.onstatechange = null;
    client.onerror = null;
    client.disconnect();
  }
  container.replaceChildren();
  showStatus('Connexion au navigateur…');

  const tunnel = new PipelinedTunnel('/tunnel', tunnelConcurrency());
  const guac = new Guacamole.Client(tunnel);
  client = guac;
  window.__remoteBrowser = { client: guac, tunnel }; // utile au diagnostic depuis la console

  const display = guac.getDisplay();
  const element = display.getElement();
  container.appendChild(element);
  display.onresize = rescale;
  display.oncursor = (canvas, x, y) => {
    element.style.cursor = `url(${canvas.toDataURL('image/png')}) ${x} ${y}, auto`;
  };

  // Souris
  const mouse = new Guacamole.Mouse(element);
  mouse.onEach(['mousedown', 'mousemove', 'mouseup'], (e) => {
    if (client === guac) guac.sendMouseState(e.state, true);
  });

  // Écrans tactiles : le doigt agit comme un pointeur.
  const touch = new Guacamole.Mouse.Touchscreen(element);
  touch.onEach(['mousedown', 'mousemove', 'mouseup'], (e) => {
    if (client === guac) guac.sendMouseState(e.state, true);
  });

  guac.onclipboard = (stream, mimetype) => {
    if (!/^text\//.test(mimetype)) return;
    const reader = new Guacamole.StringReader(stream);
    let data = '';
    reader.ontext = (text) => (data += text);
    reader.onend = () => {
      lastClipboard = data;
      if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(data).catch(() => {});
    };
  };

  guac.onstatechange = (state) => {
    if (client !== guac) return;
    if (state === STATE.CONNECTED) {
      retryDelay = 1000;
      hideStatus();
      rescale();
      container.focus();
    } else if (state === STATE.CONNECTING || state === STATE.WAITING) {
      showStatus('Connexion au navigateur…');
    } else if (state === STATE.DISCONNECTED) {
      scheduleReconnect('Connexion interrompue.');
    }
  };

  guac.onerror = (status) => {
    if (client !== guac) return;
    if (status.code === STATUS.CLIENT_UNAUTHORIZED) {
      // Session expirée : retour à la page de connexion.
      window.location.href = '/__auth/login?next=/';
      return;
    }
    const message =
      status.code === STATUS.UPSTREAM_NOT_FOUND || status.code === STATUS.UPSTREAM_UNAVAILABLE
        ? 'Le navigateur distant ne répond pas.'
        : status.code === STATUS.UPSTREAM_TIMEOUT
          ? 'Le serveur ne répond plus.'
          : `Erreur de connexion (${status.message || status.code}).`;
    guac.onstatechange = null;
    scheduleReconnect(message);
  };

  const { width, height } = viewportSize();
  const params = new URLSearchParams({
    width: String(width),
    height: String(height),
    dpi: String(Math.round(96 * Math.min(window.devicePixelRatio || 1, 2))),
    timezone: Intl.DateTimeFormat().resolvedOptions().timeZone || '',
  });
  guac.connect(params.toString());
}

// ---------------------------------------------------------------------------
// Clavier (capturé sur toute la page, sauf quand le menu ou la boîte de dialogue est ouvert)
// ---------------------------------------------------------------------------

const keyboard = new Guacamole.Keyboard(document);
keyboard.onkeydown = (keysym) => {
  if (uiCapturesKeyboard || !client) return true;
  client.sendKeyEvent(1, keysym);
  return false;
};
keyboard.onkeyup = (keysym) => {
  if (uiCapturesKeyboard || !client) return;
  client.sendKeyEvent(0, keysym);
};
window.addEventListener('blur', () => keyboard.reset());

// ---------------------------------------------------------------------------
// Fenêtres et bureaux : combinaisons envoyées au gestionnaire de fenêtres distant
// (Alt+Tab etc. sont interceptés par votre système, d'où ces commandes).
// ---------------------------------------------------------------------------

// XF86Launch5/6 : touches réservées au gestionnaire de fenêtres distant (openbox-rc.xml).
const KEY = { super: 0xffeb, ctrl: 0xffe3, nextWindow: 0x1008ff45, closeWindow: 0x1008ff46 };

function sendCombo(...keysyms) {
  if (!client) return;
  for (const k of keysyms) client.sendKeyEvent(1, k);
  for (const k of [...keysyms].reverse()) client.sendKeyEvent(0, k);
}

const WINDOW_ACTIONS = {
  'next-window': () => sendCombo(KEY.nextWindow),
  'close-window': () => sendCombo(KEY.closeWindow),
  'desktop-1': () => sendCombo(KEY.super, 0x31),
  'desktop-2': () => sendCombo(KEY.super, 0x32),
  'desktop-3': () => sendCombo(KEY.super, 0x33),
  'desktop-4': () => sendCombo(KEY.super, 0x34),
  'send-1': () => sendCombo(KEY.ctrl, KEY.super, 0x31),
  'send-2': () => sendCombo(KEY.ctrl, KEY.super, 0x32),
  'send-3': () => sendCombo(KEY.ctrl, KEY.super, 0x33),
  'send-4': () => sendCombo(KEY.ctrl, KEY.super, 0x34),
};

// ---------------------------------------------------------------------------
// Menu
// ---------------------------------------------------------------------------

function setMenuOpen(open) {
  menu.hidden = !open;
  toolbar.classList.toggle('open', open);
  menuButton.setAttribute('aria-expanded', String(open));
}

menuButton.addEventListener('click', (e) => {
  e.stopPropagation();
  setMenuOpen(menu.hidden);
});
document.addEventListener('mousedown', (e) => {
  if (!toolbar.contains(e.target)) setMenuOpen(false);
});

menu.addEventListener('click', (e) => {
  const qualityItem = e.target.closest('[data-quality]');
  if (qualityItem) {
    quality = qualityItem.dataset.quality;
    try {
      localStorage.setItem('rb-quality', quality);
    } catch {}
    updateQualityMenu();
    setMenuOpen(false);
    if (client) client.sendSize(viewportSize().width, viewportSize().height);
    return;
  }
  const action = e.target.closest('[data-action]')?.dataset.action;
  if (!action) return;
  setMenuOpen(false);
  if (WINDOW_ACTIONS[action]) {
    WINDOW_ACTIONS[action]();
    container.focus();
  } else if (action === 'fullscreen') {
    if (document.fullscreenElement) document.exitFullscreen();
    else document.documentElement.requestFullscreen?.().catch(() => {});
  } else if (action === 'paste') {
    keyboard.reset();
    uiCapturesKeyboard = true;
    pasteText.value = '';
    pasteDialog.showModal();
    pasteText.focus();
  } else if (action === 'reconnect') {
    retryDelay = 1000;
    connect();
  }
});

pasteDialog.addEventListener('close', () => {
  uiCapturesKeyboard = false;
  if (pasteDialog.returnValue === 'send') sendClipboard(pasteText.value);
  container.focus();
});

reconnectButton.addEventListener('click', () => {
  retryDelay = 1000;
  connect();
});

window.addEventListener('beforeunload', () => client && client.disconnect());

updateQualityMenu();
connect();
