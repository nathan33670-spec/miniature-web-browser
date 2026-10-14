'use strict';

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
}

const STYLE = `
:root { color-scheme: light dark; --bg:#f3f4f6; --card:#fff; --fg:#111827; --muted:#6b7280; --border:#d1d5db; --accent:#2563eb; --accent-fg:#fff; --error-bg:#fef2f2; --error-fg:#b91c1c; }
@media (prefers-color-scheme: dark) { :root { --bg:#0b0f19; --card:#151b2b; --fg:#e5e7eb; --muted:#9ca3af; --border:#2c3548; --accent:#3b82f6; --error-bg:#3b1416; --error-fg:#fca5a5; } }
* { box-sizing: border-box; }
body { margin:0; min-height:100vh; display:flex; align-items:center; justify-content:center; padding:16px; background:var(--bg); color:var(--fg); font:15px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif; }
main { width:100%; max-width:380px; background:var(--card); border:1px solid var(--border); border-radius:14px; padding:28px; box-shadow:0 10px 30px rgba(0,0,0,.08); }
h1 { margin:0 0 4px; font-size:20px; }
p.sub { margin:0 0 22px; color:var(--muted); font-size:14px; }
label { display:block; font-size:13px; font-weight:600; margin:14px 0 6px; }
input { width:100%; padding:10px 12px; border:1px solid var(--border); border-radius:8px; background:transparent; color:inherit; font:inherit; }
input:focus { outline:2px solid var(--accent); outline-offset:1px; border-color:transparent; }
button { width:100%; margin-top:22px; padding:11px; border:0; border-radius:8px; background:var(--accent); color:var(--accent-fg); font:inherit; font-weight:600; cursor:pointer; }
.error { margin:0 0 6px; padding:10px 12px; border-radius:8px; background:var(--error-bg); color:var(--error-fg); font-size:14px; }
.logo { width:36px; height:36px; margin-bottom:14px; }
`;

const LOGO = `<svg class="logo" viewBox="0 0 48 48" aria-hidden="true"><circle cx="24" cy="24" r="22" fill="#2563eb"/><circle cx="24" cy="24" r="9" fill="#fff"/><circle cx="24" cy="24" r="6" fill="#2563eb"/></svg>`;

function layout(title, body) {
  return `<!doctype html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>${escapeHtml(title)}</title>
<style>${STYLE}</style>
</head>
<body><main>${LOGO}${body}</main></body>
</html>`;
}

function loginPage({ error = '', next = '/', totp = false, username = '' } = {}) {
  return layout(
    'Connexion — Navigateur distant',
    `<h1>Navigateur distant</h1>
<p class="sub">Accès réservé. Identifiez-vous pour continuer.</p>
${error ? `<p class="error" role="alert">${escapeHtml(error)}</p>` : ''}
<form method="post" action="/__auth/login" autocomplete="on">
<input type="hidden" name="next" value="${escapeHtml(next)}">
<label for="username">Identifiant</label>
<input id="username" name="username" autocomplete="username" required autofocus value="${escapeHtml(username)}">
<label for="password">Mot de passe</label>
<input id="password" name="password" type="password" autocomplete="current-password" required>
${
  totp
    ? `<label for="totp">Code de vérification (2FA)</label>
<input id="totp" name="totp" inputmode="numeric" pattern="[0-9 ]{6,7}" autocomplete="one-time-code" required>`
    : ''
}
<button type="submit">Se connecter</button>
</form>`
  );
}

function messagePage(title, message) {
  return layout(title, `<h1>${escapeHtml(title)}</h1><p class="sub">${escapeHtml(message)}</p>`);
}

module.exports = { loginPage, messagePage, escapeHtml };
