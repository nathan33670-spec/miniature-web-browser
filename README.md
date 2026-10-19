# Navigateur distant (Chromium) — accès sécurisé depuis l'extérieur

Un vrai **Chromium** qui tourne sur votre NAS et que vous utilisez depuis n'importe quel
navigateur (PC, tablette, téléphone). Toute la navigation se fait depuis le NAS : vous
profitez de sa connexion Internet sans les restrictions du réseau où vous vous trouvez.

```
 Vous ──HTTPS (requêtes HTTP classiques)──▶ gateway :8443 ──▶ guacd ──VNC──▶ desktop (Chromium)
                                            • HTTPS              (réseau Docker interne, isolé)
                                            • Connexion + 2FA
                                            • Restriction IP
                                            • Page d'affichage
```

**Aucun WebSocket** : l'affichage utilise le *tunnel HTTP* d'[Apache Guacamole](https://guacamole.apache.org/).
L'écran est transmis par une succession de courtes requêtes HTTPS ordinaires (comme du
« long polling »), ce qui traverse les proxys d'entreprise qui bloquent les WebSockets ou
qui mettent les réponses en tampon.

- **`gateway`** : passerelle Node.js écrite pour ce projet, seul port ouvert. Elle authentifie,
  filtre, sert la page d'affichage et implémente le tunnel HTTP Guacamole.
- **`guacd`** : moteur officiel Guacamole, qui convertit la session VNC. Réseau interne uniquement.
- **`desktop`** : **Chromium** (Debian) dans une session TigerVNC. Aucun port publié ; seul ce
  conteneur a accès à Internet pour naviguer.

## Sécurité

| Protection | Détail |
|---|---|
| Authentification | Un seul compte. Mot de passe stocké uniquement sous forme de hash **scrypt**. |
| Double authentification | **TOTP** optionnel (Google Authenticator, Aegis, Bitwarden…), codes à usage unique. |
| Anti-bruteforce | 5 échecs en 15 min ⇒ IP bloquée 30 min (réglable), délai à chaque échec. |
| Sessions | Cookie aléatoire `HttpOnly`, `SameSite=Strict`, `Secure` en HTTPS. Expiration après 12 h et après 2 h d'inactivité. La déconnexion coupe aussi l'affichage. |
| IPv4 uniquement | Port publié seulement en IPv4, toute connexion IPv6 refusée (même relayée par un reverse proxy). |
| Restriction IP | Optionnelle, voir plus bas. Appliquée à toutes les requêtes, tunnel compris. |
| HTTPS | Certificat auto-signé généré au premier démarrage, ou vos propres certificats. |
| Isolation | guacd et le bureau sont sur un réseau Docker interne ; le tunnel est lié à votre session et à un jeton propre ; mot de passe VNC interne ; Chromium tourne en utilisateur non-root avec son bac à sable ; passerelle en lecture seule. |

## Installation sur le NAS

```bash
git clone https://github.com/nathan33670-spec/miniature-web-browser.git
cd miniature-web-browser
cp .env.example .env
mkdir -p data/gateway data/desktop   # certains NAS (Synology) ne les créent pas seuls
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

**3. Mot de passe interne** (entre guacd et le bureau) : mettez une valeur aléatoire dans `INTERNAL_BROWSER_PASSWORD`
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
2. Pas besoin de WebSocket. Si possible, augmentez le délai de lecture du proxy
   (Synology : Paramètres avancés → 3600 s) et désactivez la mise en tampon des réponses
   (la passerelle envoie `X-Accel-Buffering: no`, respecté par nginx).
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

## Utilisation

- **Clavier et souris** sont transmis directement ; l'écran distant s'adapte à la taille de votre
  fenêtre.
- **Menu** (bouton `⋯` en haut à droite) : plein écran, envoi de texte dans le presse-papiers
  distant, reconnexion, déconnexion.
- **Presse-papiers** : ce qui est copié dans Chromium arrive dans votre presse-papiers ; votre
  presse-papiers est envoyé quand la page reprend le focus (si le navigateur l'autorise), sinon
  utilisez « Envoyer du texte… ».
- En cas de coupure réseau, la page se reconnecte automatiquement.
- Les raccourcis réservés par votre navigateur local (Ctrl+W, Ctrl+T…) restent captés par lui :
  utilisez le mode plein écran ou les menus de Chromium.
- Pas de son (le flux audio n'est pas transmis).

## Configuration de Chromium

- **Page d'accueil** : `START_URL=https://www.google.fr`.
- **Options Chromium supplémentaires** : `CHROMIUM_FLAGS=`.
- **Taille d'écran initiale** : `SCREEN_RESOLUTION=1600x900` (elle suit ensuite votre fenêtre).
- **Profil persistant** (favoris, historique, mots de passe, extensions) : `./data/desktop`.
- **Langue / fuseau** : `BROWSER_LOCALE`, `TZ`.

## Mise à jour

```bash
git pull
docker compose pull guacd
docker compose build --pull
docker compose up -d
```

`docker compose build --pull` reconstruit aussi l'image du bureau avec la dernière version de
Chromium publiée par Debian : relancez-le régulièrement pour les correctifs de sécurité.

## Référence des variables

Toutes les variables sont documentées dans [`.env.example`](.env.example).

## Développement

```bash
cd gateway
npm install && npm test     # tests unitaires et d'intégration (Node ≥ 20)
```
