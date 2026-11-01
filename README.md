# cocon-api

Serveur de [Cocon](../untitled), avec son **interface web** : inscription,
connexion, et un espace où piloter vos sessions de concentration en temps
réel, gérer vos tâches, vos réglages, vos appareils et la sécurité du compte.
L'API sert aussi la future application mobile. À héberger soi-même.

```
 navigateur ─┐
 téléphone ──┴─HTTPS/WSS─▶  cocon-api  ◀──WSS── cocon agent (votre PC)
                               │
                           PostgreSQL
```

Le PC ouvre lui-même la connexion vers le serveur : **aucun port n'est ouvert
sur votre ordinateur**.

## Sécurité

L'API peut démarrer ou arrêter une session (donc geler des applications) et
modifier vos réglages : elle est verrouillée en conséquence.

| Mesure | Détail |
|---|---|
| Inscription | au choix : libre, sur invitation (code à usage unique) ou fermée (`COCON_API_SIGNUP`) ; 5 inscriptions par heure et par IP |
| Mots de passe | Argon2id, 12 caractères minimum |
| Double authentification | TOTP (Aegis, Google Authenticator…), chaque code ne sert qu'une fois |
| Jetons | aléatoires (256 bits), seule leur empreinte SHA-256 est stockée ; accès : 15 min ; renouvellement : 30 jours, **à usage unique** — réutiliser un jeton déjà consommé (signe de vol) révoque l'appareil |
| Appareils | listés et révocables à tout moment (déconnexion immédiate) |
| Force brute | 10 tentatives de connexion / 10 min par adresse IP ; compte verrouillé 15 min après 5 échecs |
| Énumération | même réponse et même temps de calcul pour un compte inconnu et un mauvais mot de passe |
| Transport | refuse d'écouter en HTTP sur une adresse publique : HTTPS obligatoire via reverse proxy |
| Entrées | champs inconnus refusés, tailles bornées (corps 256 Kio, réglages 64 Kio, 500 tâches) |
| Base de données | rôle PostgreSQL dédié, sans privilèges ailleurs ; requêtes SQL littérales uniquement (sqlx refuse le SQL construit dynamiquement) ; opérations sensibles atomiques |
| PC | le connecteur n'exécute qu'une liste fermée d'actions, refuse les commandes expirées (30 s) et revalide chaque réglage reçu ; l'arrêt respecte la friction de sortie |
| Traçabilité | journal d'audit (connexions, échecs, révocations, démarrages et arrêts) |
| Navigateur | session dans un cookie `__Host-cocon` (`HttpOnly`, `Secure`, `SameSite=Strict`) que le JavaScript ne peut pas lire ; toute modification exige la même origine et un en-tête anti-CSRF ; le WebSocket vérifie l'origine |
| Page web | CSP stricte (scripts et styles du serveur uniquement, rien en ligne, aucune ressource tierce) ; aucune donnée insérée en HTML brut |
| Actions sensibles | changer de mot de passe, gérer la double authentification ou supprimer le compte redemandent le mot de passe ; un changement de mot de passe déconnecte les autres appareils |
| En-têtes | `no-store`, `nosniff`, `DENY`, CSP, HSTS |

Limite à connaître : quelqu'un qui contrôlerait votre serveur pourrait
démarrer ou arrêter vos sessions et changer vos réglages (apps autorisées,
sites bloqués). Il ne peut rien exécuter d'autre sur votre PC.

## Installation

### 1. PostgreSQL : un rôle dédié

Connecté en administrateur (`psql`) :

```sql
CREATE ROLE cocon_api LOGIN PASSWORD 'un-long-mot-de-passe-aléatoire'
    NOSUPERUSER NOCREATEDB NOCREATEROLE;
CREATE DATABASE cocon_api OWNER cocon_api;
REVOKE ALL ON DATABASE cocon_api FROM PUBLIC;
```

Ne connectez jamais l'API avec un superutilisateur. Pour qu'un rôle ne puisse
même pas se connecter aux autres bases du serveur :
`REVOKE CONNECT ON DATABASE <autre_base> FROM PUBLIC;` (vérifiez d'abord
qu'aucune autre application ne compte sur ce droit par défaut).

### 2. Configuration

```sh
cp .env.example .env
chmod 600 .env
# puis renseignez DATABASE_URL
```

### 3. Compilation

```sh
cargo build --release
```

Créez ensuite votre compte depuis l'interface web (bouton « Inscription »),
ou en ligne de commande : `./target/release/cocon-api user add vous@exemple.org`.
Activez la double authentification dans **Sécurité**.

Inscriptions (`COCON_API_SIGNUP` dans `.env`, ou `--signup`) :

| Mode | Effet |
|---|---|
| `open` (par défaut) | tout le monde peut créer un compte ; l'adresse est confirmée par un code à 6 chiffres envoyé par e-mail (envoi d'e-mails obligatoire : Resend ou SMTP, voir ci-dessous) ; chaque compte ne voit que ses propres PC |
| `invite` | un code est demandé : `cocon-api invite --days 7` en crée un, à usage unique |
| `closed` | inscriptions fermées ; comptes créés en ligne de commande |

Pour un serveur personnel, `invite` ou `closed` une fois votre compte créé.

**Envoi d'e-mails.** En mode `open`, l'inscription se fait en deux
étapes : e-mail et mot de passe, puis le code à 6 chiffres reçu par e-mail
(valable 10 minutes, 5 essais, renvoi possible après une minute, 5 envois au
plus). Sans confirmation, le compte ne peut pas se connecter et il est supprimé
au bout de 24 h. Le serveur refuse de démarrer en mode `open` si le SMTP n'est
pas configuré. Le même SMTP sert à `cocon-api invite --email ami@exemple.org`.

Deux façons d'envoyer, au choix :

- **Resend** (recommandé) : `RESEND_API_KEY` (clé [Resend](https://resend.com)),
  avec le domaine de l'expéditeur vérifié chez Resend. L'envoi passe par HTTPS
  (port 443), jamais bloqué par les hébergeurs. Si la clé est définie, le SMTP
  est ignoré.
- **SMTP** : beaucoup de VPS bloquent les ports SMTP sortants (465, 587).

Pour le SMTP, renseignez dans `.env` la boîte expéditrice (Hostinger par défaut) :
`COCON_SMTP_PASSWORD` (mot de passe de `contact@tkcb.pro`) et, si besoin,
`COCON_SMTP_HOST` (par défaut `smtp.hostinger.com`),
`COCON_SMTP_PORT` (465 en TLS direct, par défaut, ou 587 en STARTTLS),
`COCON_SMTP_USER` (par défaut l'adresse de l'expéditeur), `COCON_MAIL_FROM`
(par défaut `Cocon <contact@tkcb.pro>`) et, au besoin, `COCON_PUBLIC_URL`
(adresse de l'interface, citée dans les invitations). La connexion est toujours
chiffrée. Si l'envoi d'une invitation échoue, le code est affiché pour ne pas
être perdu ; si l'envoi d'un code d'inscription échoue, le compte en attente est
supprimé et la personne est invitée à réessayer.

### 4. Service et HTTPS

L'API écoute sur `127.0.0.1:8787` ; un reverse proxy fournit le HTTPS. Avec
[Caddy](https://caddyserver.com) (certificat automatique) :

```
cocon.exemple.org {
    reverse_proxy 127.0.0.1:8787
}
```

Service systemd (`/etc/systemd/system/cocon-api.service`) :

```ini
[Unit]
Description=cocon-api
After=network-online.target postgresql.service

[Service]
User=cocon-api
WorkingDirectory=/opt/cocon-api
EnvironmentFile=/opt/cocon-api/.env
ExecStart=/opt/cocon-api/cocon-api serve
Restart=on-failure
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

### Variante : Docker

Le dossier `deploy/` lance tout d'un coup : PostgreSQL (rôle dédié créé au
premier démarrage), cocon-api et Caddy (HTTPS automatique). Le domaine doit
déjà pointer vers le serveur, ports 80 et 443 ouverts.

```sh
cd deploy
cp .env.example .env && chmod 600 .env   # domaine et mots de passe
docker compose up -d --build
docker compose exec cocon-api cocon-api user add vous@exemple.org
```

Les autres commandes passent de la même façon
(`docker compose exec cocon-api cocon-api invite`, `… audit`). Mises à jour
(Cocon et correctifs de sécurité de PostgreSQL et Caddy), à faire
régulièrement : `docker compose pull && docker compose build --pull && docker compose up -d`. Les données vivent dans le volume
`cocon_postgres` ; sauvegarde :
`docker compose exec postgres pg_dump -U postgres cocon_api > cocon.sql`.

### Variante : Coolify

Coolify construit le `Dockerfile` et fournit le domaine et le HTTPS ; la base
PostgreSQL est une ressource Coolify à part.

1. Poussez le projet sur un dépôt Git (GitHub, GitLab, Gitea…).
2. Base : **New Resource → PostgreSQL**. Créez-y de préférence un rôle et une
   base dédiés (voir l'étape 2 plus haut) plutôt que d'utiliser `postgres`.
3. Application : **New Resource → Application**, votre dépôt, build pack
   **Dockerfile**, port **8787**, votre domaine (`https://cocon.exemple.org`).
   Pas de « Ports Mappings » : seul le proxy de Coolify doit joindre l'API.
4. Variables d'environnement de l'application :
   `DATABASE_URL=postgres://cocon_api:MOT_DE_PASSE@HÔTE_INTERNE:5432/cocon_api`
   (hôte interne : l'« Internal URL » de la base dans Coolify), et au besoin
   `COCON_API_SIGNUP` (`invite` par défaut). Déployez.
5. Créez votre compte dans le **Terminal** de l'application :
   `cocon-api user add vous@exemple.org`.

L'image écoute sur `0.0.0.0:8787` avec `COCON_API_BEHIND_PROXY=true` : l'API
croit l'adresse client transmise par un proxy du réseau privé. Si Cloudflare
(nuage orange) est devant, toutes les connexions sembleront venir de ses
adresses : préférez le mode DNS seul. Sauvegardes : activez les sauvegardes
programmées de la base dans Coolify.

### 5. Relier votre PC

Sur le PC (Cocon installé) :

```sh
cocon account login https://cocon.exemple.org
systemctl --user enable --now cocon-agent
```

## Interface web

Ouvrez l'adresse du serveur dans un navigateur.

- **Session** : chaque PC relié, dessiné comme une lune qui se remplit au fil
  de la phase, avec le temps restant, les applications en pause et les
  objectifs, mis à jour en direct. Démarrez une session, ou arrêtez-la en
  respectant la friction choisie (phrase à taper, ou bouton à maintenir).
- **Tâches** : ajoutez, cochez, étoilez celles de la prochaine session.
- **Hydratation** : quantité bue aujourd'hui (y compris sur les PC reliés),
  un verre ou 500 ml en un clic, et réglages (objectif en ml, contenance du
  verre, fréquence et plage horaire des rappels). Le
  rappel s'affiche en bandeau, et en notification du navigateur si vous
  l'autorisez.
- **Réglages** : durée, rythme Pomodoro, friction, sites bloqués,
  notifications, applications autorisées ; appliqués au PC dès
  l'enregistrement.
- **Appareils** : tout ce qui est connecté au compte, révocable.
- **Sécurité** : mot de passe, double authentification (QR code),
  suppression du compte.

## Administration (sur le serveur)

| Commande | Effet |
|---|---|
| `cocon-api user add <e-mail>` | crée un compte |
| `cocon-api user passwd <e-mail>` | change le mot de passe et déconnecte tous les appareils |
| `cocon-api user totp <e-mail> on\|off` | double authentification |
| `cocon-api user unlock <e-mail>` | déverrouille un compte |
| `cocon-api user list` | liste les comptes |
| `cocon-api devices <e-mail>` | liste les appareils |
| `cocon-api revoke <appareil>` | révoque un appareil |
| `cocon-api invite [--days N] [--email ADRESSE]` | crée un code d'invitation à usage unique ; avec `--email`, l'envoie par e-mail (SMTP) |
| `cocon-api audit [--limit N]` | journal d'audit |

## API (v1)

Toutes les routes, sauf la connexion et le renouvellement, exigent
`Authorization: Bearer <jeton d'accès>`. Erreurs : `{"error": "<code>",
"message": "<texte>"}`.

### Authentification

| Route | Corps | Réponse |
|---|---|---|
| `POST /v1/auth/login` | `{email, password, totp?, device_name, device_kind: "mobile"\|"desktop"}` | `{access_token, expires_in, refresh_token, device_id}` |
| `POST /v1/auth/refresh` | `{refresh_token}` | nouvelle paire (l'ancien jeton devient inutilisable) |
| `POST /v1/auth/logout` | — | révoque l'appareil courant |
| `GET /v1/me` | — | `{email, totp_enabled, device_id}` |
| `GET /v1/devices` | — | appareils, avec `online` et `current` |
| `DELETE /v1/devices/{id}` | — | révoque un appareil |

Codes utiles à la connexion : `invalid_credentials`, `totp_required` (le mot
de passe est bon, demandez le code), `invalid_totp`, `too_many_attempts`.

### Session

| Route | Corps | Réponse |
|---|---|---|
| `GET /v1/session` | — | une vue par PC : `{device_id, device_name, online, status, updated}` |
| `POST /v1/session/start` | `{minutes?, device_id?}` | `{"outcome": "done"}` |
| `POST /v1/session/stop` | `{confirmation, device_id?}` | `{"outcome": "stop", "reply": …}` |

L'arrêt respecte la friction choisie sur le PC. Premier appel avec
`confirmation` vide, puis selon `reply` :

- `{"result": "stopped"}` : arrêtée ;
- `{"result": "need_phrase", "detail": "<phrase>"}` : rappelez avec la phrase
  tapée par l'utilisateur ;
- `{"result": "need_hold", "detail": 3}` : faites patienter l'utilisateur
  3 s (bouton maintenu), puis rappelez avec `"confirmation": "maintenu"`.

`device_id` est facultatif s'il n'y a qu'un PC en ligne. Erreurs : `no_agent`,
`offline`, `ambiguous`, `timeout`.

**Téléphone.** Avec le `device_id` d'un téléphone, `POST /v1/session/start`
lui envoie l'événement `start_focus` sur son flux `/v1/events` et répond
aussitôt `{"outcome": "done"}` ; `offline` si le téléphone n'a pas de flux
ouvert. Le téléphone démarre alors une session locale, sauf si l'utilisateur
a désactivé « Démarrage à distance ». Dans `GET /v1/devices`, `online` vaut
`true` pour un téléphone dont le flux est ouvert.

### Réglages et tâches

Versionnés : toute écriture indique la version lue ; `409 conflict` si elle a
changé entre-temps (relisez, puis réappliquez).

| Route | Corps |
|---|---|
| `GET /v1/config` | → `{version, config}` (format de `config.toml`, en JSON) |
| `PUT /v1/config` | `{version, config}` |
| `GET /v1/tasks` | → `{version, tasks: [{id, text, done, for_session, created, done_at?}]}` |
| `PUT /v1/tasks` | `{version, tasks}` |
| `POST /v1/tasks` | `{text, for_session?}` |
| `PATCH /v1/tasks/{id}` | `{text?, done?, for_session?}` |
| `DELETE /v1/tasks/{id}` | — |

Les tâches étoilées (`for_session`) deviennent les objectifs de la session
suivante ; un objectif atteint coche la tâche.

### Hydratation

C'est le serveur qui décide quand rappeler de boire, et qui prévient tous
les appareils du compte : notification sur chaque PC relié (avec un bouton
« J'ai bu un verre »), bandeau dans l'interface web, événement pour
l'application mobile. Les prises sont comptées en millilitres et portent un
identifiant : le connecteur du PC y reporte celles notées localement, même
hors connexion, et recopie celles notées ailleurs. Un rappel tombe `interval_minutes` après le dernier
rappel ou le dernier verre, uniquement dans la plage horaire choisie (heure
du fuseau `timezone`) ; il n'est jamais envoyé deux fois.

| Route | Corps | Réponse |
|---|---|---|
| `GET /v1/hydration` | — | `{settings, today, today_ml, last_drink, next_reminder, configured}` |
| `PUT /v1/hydration` | `{enabled, interval_minutes (15–240), start: "HH:MM", end: "HH:MM", goal_ml (250–6000), glass_ml (50–1000), timezone: "Europe/Paris"}` | état ; l'horloge des rappels repart de maintenant |
| `POST /v1/hydration/drink` | facultatif : `{ml (1–2000)}`, un verre sinon | état (60 prises par jour au plus) |
| `DELETE /v1/hydration/drink` | — | état (annule la dernière prise du jour) |

L'ancien champ `goal` (en verres) est encore accepté et converti en
`goal_ml` ; les réglages déjà enregistrés le sont à la lecture.

Une plage dont la fin précède le début traverse minuit (`22:00`–`02:00`).
L'historique des prises est conservé 90 jours.

### Temps réel

`GET /v1/events` (WebSocket, même en-tête `Authorization`) : à l'ouverture,
l'état de chaque PC, puis à chaque changement :

```json
{"type": "session", "device_id": "…", "online": true, "status": {"phase": "Concentration", "phase_remaining_secs": 1440, …}}
{"type": "config_changed", "version": 4}
{"type": "tasks_changed", "version": 9}
{"type": "devices_changed"}
{"type": "start_focus", "device_id": "…", "minutes": 25, "from": "Navigateur"}
{"type": "hydration_reminder", "today": 3, "goal": 8, "today_ml": 750, "goal_ml": 2000}
{"type": "hydration_changed", "settings": {…}, "today": 4, "today_ml": 1000, "last_drink": "…", "next_reminder": "…", "configured": true}
```

`/v1/agent` est réservé au connecteur des PC.

### Interface web (`/web`, cookie de session)

`POST /web/signup`, `/web/login`, `/web/logout`, `/web/password`,
`/web/totp/setup`, `/web/totp/confirm`, `/web/totp/disable`,
`/web/account/delete` ; `GET /web/info` (mode d'inscription). Les routes
`/v1` acceptent aussi le cookie, avec l'en-tête `X-Cocon-Csrf: 1` pour toute
modification.

## Développement

```sh
cargo test        # nécessite TEST_DATABASE_URL (base dédiée aux tests)
cargo clippy --all-targets -- -D warnings
```

Chaque test travaille dans un schéma PostgreSQL jetable, supprimé à la fin.
Sans `TEST_DATABASE_URL`, les tests qui ont besoin de la base sont ignorés.

Licence : GPL-3.0-or-later.
