# Navigateur distant (Chromium) — accès sécurisé depuis l'extérieur

Un vrai **Chromium** qui tourne sur votre NAS et que vous utilisez depuis n'importe quel
navigateur (PC, tablette, téléphone). Toute la navigation se fait depuis le NAS : vous
profitez de sa connexion Internet sans les restrictions du réseau où vous vous trouvez.

```
 Vous (Internet) ──HTTPS──▶  gateway :8443  ──HTTP + WebSocket (réseau Docker interne)──▶  chromium
                            • HTTPS                                                       • Chromium réel
                            • Connexion + 2FA                                             • Aucun port publié
                            • Anti-bruteforce                                             • Mot de passe interne
                            • Restriction IP
```

- **`chromium`** : image [linuxserver/chromium](https://docs.linuxserver.io/images/docker-chromium/)
  (Chromium affiché dans une page web). Elle n'est **pas exposée** : impossible de la joindre sans
  passer par la passerelle.
- **`gateway`** : petite passerelle Node.js (sans dépendance externe) écrite pour ce projet. C'est le
  seul port ouvert.

## Sécurité

| Protection | Détail |
|---|---|
| Authentification | Un seul compte. Mot de passe stocké uniquement sous forme de hash **scrypt**. |
| Double authentification | **TOTP** optionnel (Google Authenticator, Aegis, Bitwarden…), codes à usage unique. |
| Anti-bruteforce | 5 échecs en 15 min ⇒ IP bloquée 30 min (réglable), délai à chaque échec. |
| Sessions | Cookie aléatoire `HttpOnly`, `SameSite=Strict`, `Secure` en HTTPS. Expiration après 12 h et après 2 h d'inactivité. La déconnexion coupe aussi le flux vidéo. |
| IPv4 uniquement | Port publié seulement en IPv4, toute connexion IPv6 refusée (même relayée par un reverse proxy). |
| Restriction IP | Optionnelle, voir plus bas. Appliquée aussi aux WebSockets. |
| HTTPS | Certificat auto-signé généré au premier démarrage, ou vos propres certificats. |
| Défense en profondeur | Chromium protégé par un mot de passe interne que la passerelle injecte automatiquement ; conteneur passerelle en lecture seule, non-root. |

## Installation sur le NAS

```bash
git clone https://github.com/nathan33670-spec/miniature-web-browser.git
cd miniature-web-browser
cp .env.example .env
mkdir -p data/gateway data/chromium   # certains NAS (Synology) ne les créent pas seuls
docker compose build
```

**1. Mot de passe** (saisi deux fois, masqué) :

```bash
docker compose run --rm --no-deps -it gateway hash-password
```

Copiez la ligne `AUTH_PASSWORD_HASH=scrypt:...` affichée dans `.env`.

**2. Double authentification (recommandé)** :

```bash
docker compose run --rm --no-deps gateway generate-totp
```

Copiez `TOTP_SECRET=...` dans `.env` et ajoutez la clé dans votre application d'authentification.

**3. Mot de passe interne Chromium** : mettez une valeur aléatoire dans `INTERNAL_BROWSER_PASSWORD`
(`openssl rand -hex 32`). Vous n'aurez jamais à la saisir.

**4. Droits des fichiers** : réglez `PUID` / `PGID` sur l'utilisateur propriétaire du dossier
(commande `id` sur le NAS).

**5. Démarrage** :

```bash
docker compose up -d
docker compose logs -f gateway
```

Ouvrez `https://IP-DU-NAS:8443`. Avec le certificat auto-signé, le navigateur affiche un
avertissement la première fois : c'est normal, acceptez-le (ou utilisez un reverse proxy avec
un certificat Let's Encrypt, voir plus bas).

**6. Accès depuis l'extérieur** : redirigez sur votre box le port TCP choisi (ex. `8443`) vers
l'IP du NAS, ou passez par le reverse proxy du NAS.

Déconnexion : `https://…/__auth/logout`.

## Restriction par adresse IP

Par défaut (`IP_RESTRICTION_ENABLED=false`), tout le monde peut voir la page de connexion, mais
seul le mot de passe (et le code 2FA) donne accès au navigateur.

Avec `IP_RESTRICTION_ENABLED=true`, les adresses non autorisées reçoivent un **403** sans même voir
la page de connexion. L'authentification reste **toujours** obligatoire, même pour les IP autorisées.

```ini
IP_RESTRICTION_ENABLED=true
IP_ALLOWLIST=81.250.12.34, 92.184.0.0/16
```

Sont **toujours autorisés**, quelle que soit la liste :

| Source | Comment c'est géré |
|---|---|
| **localhost** | `127.0.0.0/8` et `::1` |
| **Le NAS lui-même** | La passerelle du réseau Docker (ex. `172.18.0.1`) est détectée automatiquement (`TRUST_DOCKER_GATEWAY=true`). Ajoutez aussi les IP locales du NAS dans `NAS_IPS=192.168.1.10`. |
| **Appareils derrière l'IP publique du serveur** | L'IP publique de la box est détectée automatiquement toutes les 10 min (`ALLOW_SERVER_PUBLIC_IP=true`). Vous pouvez aussi la fixer (`SERVER_PUBLIC_IP=`) ou donner votre nom DynDNS (`SERVER_PUBLIC_HOSTNAMES=monnas.ddns.net`), résolu périodiquement — pratique si votre IP change. |

Les refus sont journalisés : `docker compose logs gateway | grep refusé`.

## IPv4 uniquement

L'accès entrant est limité à l'IPv4 (`IPV4_ONLY=true`, par défaut) :

- le port est publié sur `0.0.0.0` seulement : Docker n'ouvre **aucune écoute IPv6** sur le NAS ;
- la passerelle coupe toute connexion IPv6 directe, et refuse (403) un client IPv6 relayé par
  un reverse proxy via `X-Forwarded-For` ;
- l'IP publique du serveur est détectée/résolue en IPv4 uniquement ;
- le réseau Docker interne et Chromium n'écoutent qu'en IPv4 ;
- une adresse IPv6 dans `IP_ALLOWLIST`, `NAS_IPS` ou `SERVER_PUBLIC_IP` est signalée comme
  erreur au démarrage.

Comme Docker ne relaie plus d'IPv6, aucune connexion externe ne peut se faire passer pour le NAS
via la passerelle Docker.

## Derrière un reverse proxy (Synology, Nginx Proxy Manager, Traefik…)

1. Pointez le reverse proxy vers `https://IP-DU-NAS:8443` (ou `TLS_MODE=off` et `http://…`
   si le reverse proxy est sur le même réseau et assure lui-même le HTTPS).
2. **Activez le support WebSocket** dans le reverse proxy (indispensable pour l'affichage).
3. Déclarez l'IP du reverse proxy vue par le conteneur pour que l'IP réelle du client soit
   utilisée par la restriction IP et l'anti-bruteforce :

   ```ini
   TRUSTED_PROXIES=172.16.0.0/12
   ```

   Sans cette ligne, l'en-tête `X-Forwarded-For` est ignoré (il ne peut donc pas être usurpé).

## Certificats personnalisés

Placez vos fichiers dans `./data/gateway/tls/` puis :

```ini
TLS_MODE=custom
TLS_CERT_FILE=/data/tls/fullchain.pem
TLS_KEY_FILE=/data/tls/privkey.pem
```

## Configuration de Chromium

- **Page d'accueil / options** : `CHROME_CLI=https://www.google.fr` (accepte aussi des options
  Chromium).
- **Profil persistant** (favoris, historique, extensions, sessions) : `./data/chromium`.
- **Langue / fuseau** : `BROWSER_LOCALE`, `TZ`.

## Mise à jour

```bash
git pull
docker compose pull chromium
docker compose up -d --build
```

## Référence des variables

Toutes les variables sont documentées dans [`.env.example`](.env.example).

## Développement

```bash
cd gateway
npm test     # tests unitaires et d'intégration (Node ≥ 20, aucune dépendance)
```
