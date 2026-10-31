// Cocon — interface web.
//
// Sécurité : aucune donnée n'est insérée en HTML brut (tout passe par
// textContent), la session est un cookie HttpOnly que ce script ne peut pas
// lire, et chaque requête porte l'en-tête anti-CSRF attendu par le serveur.

const app = document.getElementById("app");

const state = {
  me: null,
  info: { signup: "open" },
  sessions: new Map(), // device_id → { view, at }
  config: null, // { version, config }
  tasks: null, // { version, tasks }
  devices: null,
  hydration: null, // { settings, today, today_ml, last_drink, next_reminder }
  ws: null,
  wsRetry: 1000,
  wsSeen: 0,
};

// ------------------------------------------------------------ outils

function h(tag, props = {}, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (v == null || v === false) continue;
    if (k === "class") el.className = v;
    else if (k === "text") el.textContent = v;
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else if (v === true) el.setAttribute(k, "");
    else el.setAttribute(k, String(v));
  }
  for (const c of children.flat()) {
    if (c == null || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}

function s(tag, attrs = {}) {
  const el = document.createElementNS("http://www.w3.org/2000/svg", tag);
  for (const [k, v] of Object.entries(attrs)) el.setAttribute(k, String(v));
  return el;
}

class ApiError extends Error {
  constructor(message, code, status) {
    super(message);
    this.code = code;
    this.status = status;
  }
}

async function api(method, path, body) {
  const r = await fetch(path, {
    method,
    credentials: "same-origin",
    headers: { "content-type": "application/json", "x-cocon-csrf": "1" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  let data = null;
  if (r.status !== 204) {
    try {
      data = await r.json();
    } catch {
      data = null;
    }
  }
  if (!r.ok) {
    // Session expirée ou appareil révoqué : retour à la connexion.
    if (r.status === 401 && state.me && path.startsWith("/v1/")) {
      leave();
    }
    throw new ApiError(data?.message ?? `Erreur ${r.status}`, data?.error, r.status);
  }
  return data;
}

/// Durée restante, arrondie à la minute supérieure (comme la barre de Cocon).
function duree(secs) {
  secs = Math.max(0, Math.ceil(secs));
  if (secs < 60) return `${secs} s`;
  const total = Math.ceil(secs / 60);
  const hh = Math.floor(total / 60);
  const mm = total % 60;
  return hh > 0 ? `${hh} h ${String(mm).padStart(2, "0")}` : `${mm} min`;
}

function heure(iso) {
  const d = new Date(iso);
  return Number.isNaN(d.getTime())
    ? ""
    : d.toLocaleTimeString("fr-FR", { hour: "2-digit", minute: "2-digit" });
}

function quand(iso) {
  if (!iso) return "jamais";
  const d = new Date(iso);
  return d.toLocaleString("fr-FR", { dateStyle: "medium", timeStyle: "short" });
}

/// Logo de Cocon : cercle et croissant (même dessin que l'application).
function logo(size, cls) {
  const g = s("svg", { viewBox: "0 0 128 128", width: size, height: size, class: cls ?? "", "aria-hidden": "true" });
  g.append(
    s("circle", { cx: 64, cy: 64, r: 44, fill: "none", stroke: "currentColor", "stroke-width": 4.4 }),
    s("path", {
      fill: "currentColor",
      "fill-rule": "evenodd",
      d: "M 91.28 64 A 27.28 27.28 0 1 0 36.72 64 A 27.28 27.28 0 1 0 91.28 64 Z M 100.08 54.32 A 22.88 22.88 0 1 0 54.32 54.32 A 22.88 22.88 0 1 0 100.08 54.32 Z",
    }),
  );
  return g;
}

/// Icône de déconnexion (porte et flèche), au trait.
function iconeSortie() {
  const g = s("svg", {
    viewBox: "0 0 24 24",
    fill: "none",
    stroke: "currentColor",
    "stroke-width": 1.6,
    "stroke-linecap": "round",
    "stroke-linejoin": "round",
    "aria-hidden": "true",
  });
  g.append(
    s("path", { d: "M15 4h3a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2h-3" }),
    s("path", { d: "M10 17l-5-5 5-5" }),
    s("path", { d: "M5 12h11" }),
  );
  return g;
}

/// Icône de réglages (curseurs), au trait.
function iconeReglages() {
  const g = s("svg", { viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", "stroke-width": 1.6, "stroke-linecap": "round", "aria-hidden": "true" });
  g.append(
    s("path", { d: "M4 7h10M18 7h2M4 17h4M12 17h8" }),
    s("circle", { cx: 16, cy: 7, r: 2 }),
    s("circle", { cx: 10, cy: 17, r: 2 }),
  );
  return g;
}

function marque() {
  const m = h("div", { class: "marque" });
  m.append(logo(34), h("span", { text: "Cocon" }));
  return m;
}

/// Applique un style après deux images, pour que la transition CSS parte
/// de l'état initial d'un élément tout juste inséré.
function ensuite(fn) {
  requestAnimationFrame(() => requestAnimationFrame(fn));
}

const sansAnimation = matchMedia("(prefers-reduced-motion: reduce)").matches;

/// Fait défiler un nombre jusqu'à sa valeur ; `fmt` met en forme.
function compter(el, vers, fmt = String, depuis = 0) {
  if (sansAnimation || depuis === vers) {
    el.textContent = fmt(vers);
    return;
  }
  const t0 = performance.now();
  const pas = (t) => {
    const p = Math.min(1, (t - t0) / 700);
    const e = 1 - (1 - p) ** 3;
    el.textContent = fmt(Math.round(depuis + (vers - depuis) * e));
    if (p < 1 && el.isConnected !== false) requestAnimationFrame(pas);
  };
  el.textContent = fmt(depuis);
  requestAnimationFrame(pas);
}

/// Boîte de dialogue modale ; `build(close)` renvoie son contenu.
function dialog(build, cls) {
  return new Promise((resolve) => {
    const d = h("dialog", { class: cls });
    const close = (value) => {
      d.close();
      d.remove();
      resolve(value);
    };
    d.addEventListener("cancel", (e) => {
      e.preventDefault();
      close(null);
    });
    d.append(build(close));
    document.body.append(d);
    d.showModal();
  });
}

// ------------------------------------------------------------ démarrage

async function boot() {
  try {
    state.info = await api("GET", "/web/info");
  } catch {
    // Valeurs par défaut.
  }
  try {
    state.me = await api("GET", "/v1/me");
  } catch {
    state.me = null;
  }
  render();
}

function leave() {
  state.me = null;
  state.sessions.clear();
  state.config = state.tasks = state.devices = state.hydration = null;
  fermerRappel();
  if (state.ws) {
    state.ws.onclose = null;
    state.ws.close();
    state.ws = null;
  }
  render();
}

function render() {
  app.replaceChildren(state.me ? espace() : accueil());
}

window.addEventListener("hashchange", () => {
  if (!state.me) return;
  render();
  scrollTo({ top: 0 });
});

/// Va sur une page : le rendu passe par `hashchange`, une seule fois.
function allerA(page) {
  if (location.hash === `#/${page}`) render();
  else location.hash = `#/${page}`;
}

// ------------------------------------------------------------ connexion / inscription

/// Longueur minimale imposée par le serveur (`auth::MIN_PASSWORD_LEN`).
const MIN_PASSWORD = 12;

let champIds = 0;

/// Champ de formulaire : libellé, saisie, aide et erreur reliées pour les
/// lecteurs d'écran (`aria-describedby`), erreur affichée sous la saisie.
function champ(label, input, { aide, suffixe } = {}) {
  const id = `champ-${++champIds}`;
  input.id = id;
  const aideEl = aide ? h("p", { class: "champ-aide", id: `${id}-aide` }, aide) : null;
  const erreur = h("p", { class: "champ-erreur", id: `${id}-erreur`, "aria-live": "polite" });
  input.setAttribute("aria-describedby", [aideEl && aideEl.id, erreur.id].filter(Boolean).join(" "));
  const saisie = suffixe ? h("div", { class: "saisie" }, input, suffixe) : input;
  const el = h("div", { class: "champ" }, h("label", { for: id, text: label }), saisie, aideEl, erreur);
  return {
    el,
    input,
    aide: aideEl,
    erreur(msg) {
      erreur.textContent = msg ?? "";
      if (msg) input.setAttribute("aria-invalid", "true");
      else input.removeAttribute("aria-invalid");
    },
  };
}

/// Bouton « afficher / masquer » d'un mot de passe.
function oeil(input) {
  const b = h("button", {
    type: "button",
    class: "oeil",
    "aria-pressed": "false",
    "aria-label": "Afficher le mot de passe",
    title: "Afficher le mot de passe",
  });
  const icone = () => {
    const visible = input.type === "text";
    const g = s("svg", { viewBox: "0 0 24 24", width: 20, height: 20, "aria-hidden": "true", fill: "none", stroke: "currentColor", "stroke-width": 1.8, "stroke-linecap": "round" });
    g.append(
      s("path", { d: "M2.5 12s3.5-6.5 9.5-6.5 9.5 6.5 9.5 6.5-3.5 6.5-9.5 6.5S2.5 12 2.5 12Z" }),
      s("circle", { cx: 12, cy: 12, r: 3 }),
    );
    if (visible) g.append(s("path", { d: "M4 20 20 4" }));
    b.replaceChildren(g);
  };
  b.addEventListener("click", () => {
    const visible = input.type === "password";
    input.type = visible ? "text" : "password";
    const texte = visible ? "Masquer le mot de passe" : "Afficher le mot de passe";
    b.setAttribute("aria-pressed", String(visible));
    b.setAttribute("aria-label", texte);
    b.title = texte;
    icone();
    input.focus();
  });
  icone();
  return b;
}

/// Solidité indicative d'un mot de passe : 0 (insuffisant) à 3 (excellent).
/// Le serveur n'impose que la longueur ; la longueur reste le critère
/// principal, la variété ne fait que compléter.
function solidite(motDePasse, email) {
  const n = [...motDePasse].length;
  if (n < MIN_PASSWORD) return { niveau: 0, texte: `Encore ${MIN_PASSWORD - n} caractère${MIN_PASSWORD - n > 1 ? "s" : ""}` };
  const local = email.split("@")[0].toLowerCase();
  if (local.length >= 4 && motDePasse.toLowerCase().includes(local)) {
    return { niveau: 1, texte: "Évitez d'y reprendre votre adresse e-mail" };
  }
  if (/^(.)\1+$/.test(motDePasse)) return { niveau: 1, texte: "Évitez de répéter un seul caractère" };
  const mots = motDePasse.trim().split(/\s+/).length;
  const classes = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^a-zA-Z0-9]/].filter((r) => r.test(motDePasse)).length;
  if (n >= 20 || mots >= 4) return { niveau: 3, texte: "Excellent" };
  if (n >= 16 || classes >= 3) return { niveau: 2, texte: "Bon" };
  return { niveau: 1, texte: "Correct, un mot de plus le rendrait plus sûr" };
}

function accueil() {
  const page = h("div", { class: "accueil" });

  const ciel = h("section", { class: "ciel" });
  ciel.append(
    marque(),
    logo(420, "astre"),
    h(
      "div",
      {},
      h("h1", { text: "Votre concentration, où que vous soyez." }),
      h("p", {
        text: "Démarrez une session sur votre ordinateur depuis votre téléphone, suivez le temps qui reste et vos objectifs, arrêtez quand c'est le moment.",
      }),
    ),
  );

  // Lien d'invitation : https://serveur/?invite=CODE (ouvre l'inscription).
  const codeInvite = new URLSearchParams(location.search).get("invite")?.trim() ?? "";
  const inscriptionOuverte = state.info.signup !== "closed";
  // L'adresse saisie suit d'un formulaire à l'autre.
  const partage = { email: "" };

  const zone = h("section", { class: "formulaire" });
  const onglets = h("div", { class: "bascule", role: "tablist", "aria-label": "Connexion ou inscription" });
  const panneau = h("div", { class: "formulaire-panneau", role: "tabpanel" });
  const onglet = (id, label) =>
    h("button", { type: "button", role: "tab", id: `onglet-${id}`, onclick: () => afficher(id) }, label);
  const tabs = { connexion: onglet("connexion", "Connexion"), inscription: onglet("inscription", "Inscription") };
  onglets.append(tabs.connexion, tabs.inscription);
  onglets.hidden = !inscriptionOuverte;
  // Flèches gauche / droite entre les onglets (motif ARIA « tabs »).
  onglets.addEventListener("keydown", (e) => {
    if (e.key !== "ArrowLeft" && e.key !== "ArrowRight") return;
    const autre = document.activeElement === tabs.connexion ? "inscription" : "connexion";
    afficher(autre);
    tabs[autre].focus();
  });

  function afficher(mode) {
    if (mode === "inscription" && !inscriptionOuverte) mode = "connexion";
    // L'étape de vérification prolonge l'onglet « Inscription ».
    const onglet = mode === "verification" ? "inscription" : mode;
    for (const [id, b] of Object.entries(tabs)) {
      const actif = id === onglet;
      b.setAttribute("aria-selected", String(actif));
      b.setAttribute("aria-pressed", String(actif));
      b.tabIndex = actif ? 0 : -1;
    }
    panneau.setAttribute("aria-labelledby", `onglet-${onglet}`);
    const f =
      mode === "connexion"
        ? formConnexion(partage, afficher)
        : mode === "verification"
          ? formVerification(partage, afficher)
          : formInscription(partage, afficher, codeInvite);
    panneau.replaceChildren(f.el);
    queueMicrotask(() => f.focus());
    // L'adresse de la page reflète le formulaire affiché (lien partageable).
    const hash = onglet === "inscription" ? "#/inscription" : "";
    if (location.hash !== hash) history.replaceState(null, "", location.pathname + location.search + hash);
  }

  zone.append(h("div", { class: "formulaire-corps" }, onglets, panneau));
  page.append(ciel, zone);
  afficher(location.hash === "#/inscription" || codeInvite ? "inscription" : "connexion");
  return page;
}

function formConnexion(partage, afficher) {
  const error = h("p", { class: "erreur", role: "alert" });
  const email = champ(
    "Adresse e-mail",
    h("input", { type: "email", autocomplete: "username", required: true, maxlength: 254, value: partage.email }),
  );
  const pw = h("input", { type: "password", autocomplete: "current-password", required: true, maxlength: 1024 });
  const password = champ("Mot de passe", pw, { suffixe: oeil(pw) });
  const totp = champ(
    "Code de double authentification",
    h("input", { type: "text", inputmode: "numeric", autocomplete: "one-time-code", pattern: "[0-9 ]{6,8}", maxlength: 8 }),
    { aide: "Les 6 chiffres affichés par votre application d'authentification." },
  );
  totp.el.hidden = true;
  const submit = h("button", { class: "bouton principal", type: "submit", text: "Se connecter" });
  email.input.addEventListener("input", () => (partage.email = email.input.value));

  const form = h(
    "form",
    {
      novalidate: true,
      onsubmit: async (e) => {
        e.preventDefault();
        error.textContent = "";
        if (!email.input.value.trim() || !pw.value) {
          error.textContent = "Entrez votre adresse e-mail et votre mot de passe.";
          (email.input.value.trim() ? pw : email.input).focus();
          return;
        }
        submit.disabled = true;
        form.setAttribute("aria-busy", "true");
        try {
          state.me = await api("POST", "/web/login", {
            email: email.input.value,
            password: pw.value,
            totp: totp.el.hidden ? null : totp.input.value,
          });
          allerA("accueil");
        } catch (err) {
          if (err.code === "totp_required") {
            totp.el.hidden = false;
            totp.input.focus();
          } else if (err.code === "email_unverified") {
            // Un nouveau code vient d'être envoyé : étape de vérification.
            partage.email = email.input.value.trim();
            afficher("verification");
          } else {
            error.textContent = err.message;
          }
        } finally {
          submit.disabled = false;
          form.removeAttribute("aria-busy");
        }
      },
    },
    h("header", { class: "formulaire-titre" }, h("h2", { text: "Bon retour" }), h("p", { class: "discret", text: "Connectez-vous pour piloter vos sessions." })),
    email.el,
    password.el,
    totp.el,
    error,
    submit,
    state.info.signup !== "closed"
      ? h(
          "p",
          { class: "formulaire-pied discret" },
          "Pas encore de compte ? ",
          h("button", { type: "button", class: "bouton lien", onclick: () => afficher("inscription") }, "Créer un compte"),
        )
      : null,
  );
  return { el: form, focus: () => (email.input.value ? pw : email.input).focus() };
}

function formInscription(partage, afficher, codeInvite) {
  const surInvitation = state.info.signup === "invite";
  const error = h("p", { class: "erreur", role: "alert" });

  const email = champ(
    "Adresse e-mail",
    h("input", { type: "email", autocomplete: "email", required: true, maxlength: 254, value: partage.email }),
    { aide: "Elle sert à vous connecter. Elle n'est jamais affichée ni partagée." },
  );
  const pw = h("input", { type: "password", autocomplete: "new-password", required: true, minlength: MIN_PASSWORD, maxlength: 1024 });
  const password = champ("Mot de passe", pw, {
    suffixe: oeil(pw),
    aide: `Au moins ${MIN_PASSWORD} caractères. Une phrase de quelques mots est idéale.`,
  });
  // Jauge de solidité : quatre segments, texte lu par les lecteurs d'écran.
  const jauge = h("div", { class: "jauge", "aria-hidden": "true" }, h("span"), h("span"), h("span"), h("span"));
  const verdict = h("span", { class: "jauge-texte" });
  const indicateur = h("div", { class: "solidite", hidden: true }, jauge, verdict);
  password.el.insertBefore(indicateur, password.aide);

  const invite = champ(
    "Code d'invitation",
    h("input", { type: "text", autocomplete: "off", spellcheck: "false", maxlength: 200, value: codeInvite }),
    { aide: "Ce serveur est sur invitation : le code vous a été transmis avec le lien." },
  );
  invite.el.hidden = !surInvitation;

  const submit = h("button", { class: "bouton principal", type: "submit", text: "Créer mon compte" });

  const majSolidite = () => {
    const vide = pw.value === "";
    indicateur.hidden = vide;
    password.aide.hidden = !vide;
    if (vide) return;
    const { niveau, texte } = solidite(pw.value, email.input.value);
    jauge.dataset.niveau = String(niveau);
    verdict.textContent = texte;
  };

  // Vérifications locales (le serveur revalide tout).
  const verifs = {
    email: () => {
      const v = email.input.value.trim();
      if (!v) return "Entrez votre adresse e-mail.";
      // Même règle que le serveur (`clean_email`) : domaine avec un point.
      const [local, domaine] = v.split(/@(?=[^@]*$)/);
      const ok = v.includes("@") && local && domaine?.includes(".") && !/^\.|\.$/.test(domaine) && !/\s/.test(v);
      if (!ok) return "Cette adresse ne semble pas valide (exemple : nom@domaine.fr).";
      return null;
    },
    password: () => ([...pw.value].length < MIN_PASSWORD ? `Le mot de passe doit faire au moins ${MIN_PASSWORD} caractères.` : null),
    invite: () => (surInvitation && !invite.input.value.trim() ? "Entrez votre code d'invitation." : null),
  };
  const champs = { email, password, invite };
  // Une erreur n'apparaît qu'après la première sortie du champ, puis suit la saisie.
  const touches = new Set();
  for (const [nom, c] of Object.entries(champs)) {
    c.input.addEventListener("blur", () => {
      if (c.input.value === "") return;
      touches.add(nom);
      c.erreur(verifs[nom]());
    });
    c.input.addEventListener("input", () => {
      if (touches.has(nom)) c.erreur(verifs[nom]());
      error.textContent = "";
    });
  }
  email.input.addEventListener("input", () => {
    partage.email = email.input.value;
    majSolidite();
  });
  pw.addEventListener("input", majSolidite);

  const form = h(
    "form",
    {
      novalidate: true,
      onsubmit: async (e) => {
        e.preventDefault();
        error.textContent = "";
        let premier = null;
        for (const [nom, c] of Object.entries(champs)) {
          if (c.el.hidden) continue;
          touches.add(nom);
          const msg = verifs[nom]();
          c.erreur(msg);
          if (msg && !premier) premier = c.input;
        }
        if (premier) return premier.focus();

        submit.disabled = true;
        submit.textContent = "Création du compte…";
        form.setAttribute("aria-busy", "true");
        try {
          const r = await api("POST", "/web/signup", {
            email: email.input.value.trim(),
            password: pw.value,
            invite: surInvitation ? invite.input.value.trim() : null,
          });
          if (r?.verify) {
            // Étape 2 : code à 6 chiffres envoyé par e-mail.
            partage.email = r.email;
            afficher("verification");
            return;
          }
          state.me = r;
          // Le code d'invitation ne doit pas rester dans l'adresse.
          history.replaceState(null, "", location.pathname);
          allerA("accueil");
        } catch (err) {
          if (err.code === "email_taken") {
            // Inscription déjà commencée (code jamais saisi, envoi coupé…) :
            // avec le même mot de passe, on reprend à l'étape du code.
            try {
              state.me = await api("POST", "/web/login", { email: email.input.value.trim(), password: pw.value, totp: null });
              history.replaceState(null, "", location.pathname);
              return allerA("accueil");
            } catch (e) {
              if (e.code === "email_unverified") {
                partage.email = email.input.value.trim();
                return afficher("verification");
              }
            }
          }
          switch (err.code) {
            case "email_taken":
              email.erreur("Un compte existe déjà avec cette adresse.");
              email.el.querySelector(".champ-erreur").append(
                " ",
                h("button", { type: "button", class: "bouton lien", onclick: () => afficher("connexion") }, "Se connecter"),
              );
              email.input.focus();
              break;
            case "invite_required":
            case "invalid_invite":
              invite.erreur(err.message);
              invite.input.focus();
              break;
            default:
              if (err.status === 400 && /mot de passe/i.test(err.message)) {
                password.erreur(err.message);
                pw.focus();
              } else if (err.status === 400 && /adresse|e-mail/i.test(err.message)) {
                email.erreur(err.message);
                email.input.focus();
              } else {
                error.textContent =
                  err.status === 429 ? "Trop de tentatives depuis cette connexion. Réessayez dans quelques minutes." : err.message;
              }
          }
        } finally {
          submit.disabled = false;
          submit.textContent = "Créer mon compte";
          form.removeAttribute("aria-busy");
        }
      },
    },
    h(
      "header",
      { class: "formulaire-titre" },
      h("h2", { text: "Créer votre compte" }),
      h("p", { class: "discret", text: "Un compte relie votre ordinateur et votre téléphone. Cela prend moins d'une minute." }),
    ),
    email.el,
    password.el,
    invite.el,
    error,
    submit,
    h(
      "p",
      { class: "formulaire-pied discret" },
      "Déjà un compte ? ",
      h("button", { type: "button", class: "bouton lien", onclick: () => afficher("connexion") }, "Se connecter"),
    ),
  );
  majSolidite();
  return {
    el: form,
    focus: () => (surInvitation && !invite.input.value ? invite.input : email.input.value ? pw : email.input).focus(),
  };
}

/// Étape 2 de l'inscription : le code à 6 chiffres reçu par e-mail.
function formVerification(partage, afficher) {
  const adresse = partage.email.trim();
  const error = h("p", { class: "erreur", role: "alert" });
  const statut = h("p", { class: "champ-aide", "aria-live": "polite" });
  const code = champ(
    "Code reçu par e-mail",
    h("input", {
      type: "text",
      inputmode: "numeric",
      autocomplete: "one-time-code",
      spellcheck: "false",
      maxlength: 7,
      placeholder: "123456",
      class: "code-saisie",
    }),
    { aide: "Les 6 chiffres du message envoyé par contact@tkcb.pro. Pensez à regarder dans les indésirables." },
  );
  const submit = h("button", { class: "bouton principal", type: "submit", text: "Valider" });

  // « Renvoyer le code » : disponible une minute après le dernier envoi.
  const DELAI = 60;
  let attente = DELAI;
  const renvoi = h("button", { type: "button", class: "bouton lien" });
  const majRenvoi = () => {
    renvoi.disabled = attente > 0;
    renvoi.textContent = attente > 0 ? `Renvoyer le code (dans ${attente} s)` : "Renvoyer le code";
  };
  const minuteur = setInterval(() => {
    if (!renvoi.isConnected) return clearInterval(minuteur);
    if (attente > 0) {
      attente -= 1;
      majRenvoi();
    }
  }, 1000);
  majRenvoi();
  renvoi.addEventListener("click", async () => {
    error.textContent = "";
    renvoi.disabled = true;
    try {
      await api("POST", "/web/signup/resend", { email: adresse });
      statut.textContent = `Nouveau code envoyé à ${adresse}.`;
      code.input.value = "";
      code.erreur(null);
      code.input.focus();
      attente = DELAI;
    } catch (err) {
      error.textContent =
        err.status === 429 ? "Trop de tentatives depuis cette connexion. Réessayez dans quelques minutes." : err.message;
    } finally {
      majRenvoi();
    }
  });

  const chiffres = () => code.input.value.replace(/[\s-]/g, "");
  let envoiEnCours = false;
  const valider = async () => {
    if (envoiEnCours) return;
    error.textContent = "";
    if (!/^[0-9]{6}$/.test(chiffres())) {
      code.erreur("Le code se compose de 6 chiffres.");
      return code.input.focus();
    }
    envoiEnCours = true;
    submit.disabled = true;
    submit.textContent = "Vérification…";
    form.setAttribute("aria-busy", "true");
    try {
      state.me = await api("POST", "/web/signup/verify", { email: adresse, code: chiffres() });
      history.replaceState(null, "", location.pathname);
      allerA("accueil");
    } catch (err) {
      switch (err.code) {
        case "invalid_code":
          code.erreur("Code incorrect. Vérifiez les 6 chiffres reçus.");
          code.input.select();
          break;
        case "code_expired":
          code.erreur("Ce code n'est plus valable. Demandez-en un nouveau ci-dessous.");
          if (!renvoi.disabled) renvoi.focus();
          break;
        default:
          error.textContent =
            err.status === 429 ? "Trop de tentatives depuis cette connexion. Réessayez dans quelques minutes." : err.message;
      }
    } finally {
      envoiEnCours = false;
      submit.disabled = false;
      submit.textContent = "Valider";
      form.removeAttribute("aria-busy");
    }
  };
  // Validation automatique dès le 6e chiffre (saisie ou collage).
  code.input.addEventListener("input", () => {
    code.erreur(null);
    error.textContent = "";
    if (/^[0-9]{6}$/.test(chiffres())) valider();
  });

  const form = h(
    "form",
    {
      novalidate: true,
      onsubmit: (e) => {
        e.preventDefault();
        valider();
      },
    },
    h(
      "header",
      { class: "formulaire-titre" },
      h("h2", { text: "Confirmez votre adresse" }),
      h("p", { class: "discret" }, "Nous avons envoyé un code à 6 chiffres à ", h("strong", { text: adresse }), ". Il est valable 10 minutes."),
    ),
    code.el,
    error,
    submit,
    h("p", { class: "formulaire-pied discret" }, renvoi),
    statut,
    h(
      "p",
      { class: "formulaire-pied discret" },
      "Mauvaise adresse ? ",
      h("button", { type: "button", class: "bouton lien", onclick: () => afficher("inscription") }, "La modifier"),
    ),
  );
  return { el: form, focus: () => code.input.focus() };
}

// ------------------------------------------------------------ espace

const ROUTES = [
  ["accueil", "Accueil"],
  ["securite", "Sécurité"],
];

function route() {
  const r = location.hash.replace(/^#\/?/, "");
  return ROUTES.some(([id]) => id === r) ? r : "accueil";
}

let ticks = [];
setInterval(() => ticks.forEach((t) => t()), 1000);

function espace() {
  ticks = [];
  connectEvents();
  const current = route();
  const nav = h(
    "nav",
    { "aria-label": "Sections" },
    ROUTES.map(([id, label]) =>
      h("a", { href: `#/${id}`, "aria-current": id === current ? "page" : null }, label),
    ),
  );
  const out = h("button", {
    class: "rond",
    type: "button",
    "aria-label": "Se déconnecter",
    title: "Se déconnecter",
    onclick: async () => {
      try {
        await api("POST", "/web/logout");
      } finally {
        leave();
      }
    },
  }, iconeSortie());
  const compte = h(
    "span",
    { class: "compte", title: state.me.email },
    h("span", { class: "adresse", text: state.me.email }),
    h("span", { class: "initiale bleu", "aria-hidden": "true", text: state.me.email.slice(0, 1) }),
  );
  const reglages = h("button", {
    class: "rond",
    type: "button",
    "aria-label": "Réglages",
    title: "Réglages",
    onclick: ouvrirReglages,
  }, iconeReglages());
  const head = h("header", { class: "entete" }, marque(), nav, h("div", { class: "outils" }, reglages, out, compte));
  // Les cartes apparaissent en cascade au premier affichage seulement :
  // celles qui sont remplacées ensuite (temps réel) ne rejouent pas l'entrée.
  const view = h("div", { class: "vue entree" });
  setTimeout(() => view.classList.remove("entree"), 1400);
  ({ accueil: vueAccueil, securite: vueSecurite })[current](view);
  return h("div", { class: "espace" }, head, view);
}

function entete(view, titre, sousTitre) {
  view.append(h("header", {}, h("h1", { text: titre }), sousTitre ? h("p", { class: "discret", text: sousTitre }) : null));
}

// ------------------------------------------------------------ temps réel

function connectEvents() {
  if (state.ws) return;
  const url = `${location.protocol === "https:" ? "wss" : "ws"}://${location.host}/v1/events`;
  const ws = new WebSocket(url);
  state.ws = ws;
  ws.onopen = () => {
    state.wsRetry = 1000;
    state.wsSeen = Date.now();
  };
  ws.onmessage = (msg) => {
    state.wsSeen = Date.now();
    let ev;
    try {
      ev = JSON.parse(msg.data);
    } catch {
      return;
    }
    onEvent(ev);
  };
  ws.onclose = () => {
    state.ws = null;
    if (!state.me) return;
    const wait = state.wsRetry;
    state.wsRetry = Math.min(wait * 2, 30000);
    setTimeout(async () => {
      try {
        await api("GET", "/v1/me");
        connectEvents();
      } catch {
        // api() a déjà ramené à la connexion si la session est finie.
      }
    }, wait);
  };
}

// Canal muet (le serveur envoie un battement toutes les 30 s) : on le
// ferme, la reconnexion automatique prend le relais.
setInterval(() => {
  if (state.ws && state.ws.readyState === WebSocket.OPEN && Date.now() - state.wsSeen > 75000) {
    state.ws.close();
  }
}, 15000);

const sessionPanels = new Map(); // device_id → élément affiché

function onEvent(ev) {
  const r = route();
  if (ev.type === "session") {
    const before = state.sessions.get(ev.device_id);
    const same =
      before &&
      before.view.online === ev.online &&
      JSON.stringify(before.view.status) === JSON.stringify(ev.status);
    state.sessions.set(ev.device_id, { view: ev, at: Date.now() });
    if (r === "accueil" && !same) {
      const old = sessionPanels.get(ev.device_id);
      if (old) old.replaceWith(panneauPc(ev));
      else render();
    }
  } else if (ev.type === "tasks_changed" && r === "accueil") {
    if (!state.tasks || ev.version > state.tasks.version) majCartesTaches(true);
  } else if (ev.type === "config_changed" && r === "accueil") {
    // La durée et le rythme affichés au repos viennent des réglages.
    if (!state.config || ev.version > state.config.version) majReglagesAffiches();
  } else if (ev.type === "devices_changed" && r === "securite") {
    majAppareils();
  } else if (ev.type === "hydration_reminder") {
    afficherRappel(ev.today_ml, ev.goal_ml);
  } else if (ev.type === "hydration_changed") {
    // Prise notée ici ou ailleurs (PC, téléphone) : le rappel a eu sa réponse.
    const avant = state.hydration?.today_ml ?? 0;
    state.hydration = ev;
    if (ev.today_ml > avant) fermerRappel();
    majCarteEau();
  }
}

// ------------------------------------------------------------ session

/// Phase de lune : `f` = part éclairée (0 nouvelle lune, 1 pleine lune).
function phaseLune(f) {
  const r = 100;
  if (f <= 0.001) return "";
  if (f >= 0.999) return `M 0 ${-r} A ${r} ${r} 0 1 1 0 ${r} A ${r} ${r} 0 1 1 0 ${-r} Z`;
  const rx = r * Math.abs(1 - 2 * f);
  const sweep = f < 0.5 ? 0 : 1;
  return `M 0 ${-r} A ${r} ${r} 0 0 1 0 ${r} A ${rx.toFixed(2)} ${r} 0 0 ${sweep} 0 ${-r} Z`;
}

function astre(label) {
  const root = h("div", { class: "astre-session", role: "img", "aria-label": label });
  const g = s("svg", { viewBox: "-110 -110 220 220", "aria-hidden": "true" });
  const lit = s("path", { class: "eclaire", d: "" });
  g.append(s("circle", { class: "halo", r: 106 }), s("circle", { class: "disque", r: 100 }), lit);
  const minutes = h("div", { class: "minutes" });
  const unite = h("div", { class: "unite" });
  root.append(g, h("div", { class: "lecture" }, minutes, unite));
  return {
    root,
    set(f, main, sub, aria) {
      lit.setAttribute("d", phaseLune(f));
      minutes.textContent = main;
      unite.textContent = sub;
      if (aria) root.setAttribute("aria-label", aria);
    },
  };
}

async function vueAccueil(view) {
  const moment = new Date().getHours() < 18 ? "Bonjour" : "Bonsoir";
  const nom = prenom(state.me.email);
  entete(view, nom ? `${moment}, ${nom}` : moment, "Vos sessions, vos tâches et vos ordinateurs, en direct.");
  const zone = h("div", { class: "tableau" });
  view.append(zone);
  try {
    const [sessions, config, tasks, eau] = await Promise.all([
      api("GET", "/v1/session"),
      api("GET", "/v1/config").catch(() => null),
      api("GET", "/v1/tasks").catch(() => null),
      api("GET", "/v1/hydration").catch(() => null),
    ]);
    if (config) state.config = config;
    if (tasks) state.tasks = tasks;
    if (eau) state.hydration = eau;
    for (const v of sessions) {
      if (!state.sessions.has(v.device_id) || state.sessions.get(v.device_id).view.updated !== v.updated) {
        state.sessions.set(v.device_id, { view: v, at: Date.now() });
      }
    }
    const pcs = sessions.map((v) => state.sessions.get(v.device_id).view);
    sessionPanels.clear();
    if (pcs.length === 0) zone.append(bienvenue());
    for (const v of pcs) zone.append(panneauPc(v));
    const taches = carteTaches();
    const bilan = carteBilan();
    cartesTaches = { taches, bilan };
    zone.append(taches, bilan);
    if (state.hydration) {
      carteEauAffichee = carteEau();
      zone.append(carteEauAffichee);
    }
  } catch (err) {
    zone.append(h("p", { class: "erreur pleine", text: err.message }));
  }
}

/// Une commande à copier en un clic.
function commande(texte) {
  const bouton = h("button", { class: "copier", type: "button", "aria-label": `Copier : ${texte}` }, "Copier");
  bouton.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(texte);
      bouton.textContent = "Copié ✓";
    } catch {
      bouton.textContent = "Sélectionnez";
    }
    setTimeout(() => (bouton.textContent = "Copier"), 1800);
  });
  return h("div", { class: "commande" }, h("code", { text: texte }), bouton);
}

/// Premier contact : relier son PC en trois étapes. La carte laisse place
/// au tableau de bord dès que l'agent se connecte (évènement « session »).
function bienvenue() {
  const etape = (n, titre, ...contenu) =>
    h("li", { class: "etape" }, h("span", { class: "numero", text: String(n) }), h("div", {}, h("h3", { text: titre }), ...contenu));
  const moon = astre("Cocon");
  moon.set(0.35, "", "");
  return h(
    "article",
    { class: "heros bienvenue pleine" },
    h("div", { class: "haut" }, h("span", { class: "puce point attente", text: "En attente de votre PC…" }), moon.root),
    h(
      "div",
      { class: "bienvenue-corps" },
      h("div", {},
        h("p", { class: "phrase", text: "Reliez votre ordinateur pour piloter vos sessions d'ici" }),
        h("p", { class: "sous-phrase", text: "Trois étapes, une seule fois. Cette carte se met à jour toute seule dès que votre PC répond." }),
      ),
      h(
        "ol",
        { class: "etapes" },
        etape(1, "Installez Cocon", h("p", { text: "L'application de bureau, sur l'ordinateur où vous travaillez." })),
        etape(2, "Reliez-le à ce compte", commande(`cocon account login ${location.origin}`)),
        etape(3, "Lancez le connecteur", commande("cocon agent")),
      ),
    ),
    h("span", { class: "point-ciel" }),
    h("span", { class: "point-ciel" }),
    h("span", { class: "point-ciel" }),
  );
}

/// Cartes de tâches du tableau de bord, redessinées quand la liste change.
let cartesTaches = null;

async function majCartesTaches(recharger) {
  if (!cartesTaches || !cartesTaches.taches.isConnected) return;
  if (recharger) {
    try {
      state.tasks = await api("GET", "/v1/tasks");
    } catch {
      return;
    }
  }
  // Garde le volet « Terminées » ouvert s'il l'était, et le champ en cours.
  const ouvert = cartesTaches.taches.querySelector("details")?.open;
  const brouillon = cartesTaches.taches.querySelector(".ajout input[type=text]");
  const saisie = brouillon?.value ?? "";
  const focus = document.activeElement === brouillon;
  const taches = carteTaches(ouvert);
  const bilan = carteBilan();
  cartesTaches.taches.replaceWith(taches);
  cartesTaches.bilan.replaceWith(bilan);
  cartesTaches = { taches, bilan };
  const champ = taches.querySelector(".ajout input[type=text]");
  if (champ) {
    champ.value = saisie;
    if (focus) champ.focus();
  }
}

/// Réglages reçus d'ailleurs : les cartes au repos reprennent la durée et le rythme.
async function majReglagesAffiches() {
  try {
    state.config = await api("GET", "/v1/config");
  } catch {
    return;
  }
  for (const [id, panel] of sessionPanels) {
    const v = state.sessions.get(id)?.view;
    if (v && panel.isConnected) panel.replaceWith(panneauPc(v));
  }
}

/// Histogramme en colonnes : une par cycle (ou par dixième de phase).
function rythme(etiquettes) {
  const root = h("div", { class: "colonnes", "aria-hidden": "true" });
  const cols = etiquettes.map((label) => {
    const plein = h("div", { class: "plein" });
    const col = h(
      "div",
      { class: "colonne-barre" },
      h("div", { class: "pile" }, plein, h("div", { class: "hachure" })),
      h("div", { class: "etiquette", text: label }),
    );
    root.append(col);
    return { col, plein };
  });
  let premier = true;
  return {
    root,
    /// `courant` : indice en cours (-1 : aucun) ; `f` : sa part écoulée.
    set(courant, f, bulle) {
      if (premier) {
        premier = false;
        ensuite(() => this.set(courant, f, bulle));
        return;
      }
      cols.forEach(({ col, plein }, i) => {
        col.classList.toggle("fait", i < courant);
        col.classList.toggle("courant", i === courant);
        const part = i < courant ? 1 : i === courant ? 0.25 + 0.75 * f : 0.12 + 0.18 * ((i * 7) % 5) / 4;
        plein.style.height = `${Math.round(40 + 100 * part)}px`;
        plein.replaceChildren(i === courant && bulle ? h("span", { class: "bulle", text: bulle }) : "");
      });
    },
  };
}

/// Barre segmentée avec ses légendes : `[[part, classe, légende], …]`.
function segments(parts) {
  const barres = h("div", { class: "barres" });
  const legendes = h("div", { class: "legendes" });
  const els = parts.map(([part, cls, label]) => {
    const b = h("span", { class: cls });
    const l = h("span", { class: cls ? "" : "discret", text: label });
    barres.append(b);
    legendes.append(l);
    return { b, l };
  });
  const set = (values) =>
    values.forEach((part, i) => {
      const grow = Math.max(0.0001, part);
      els[i].b.style.flexGrow = String(grow);
      els[i].l.style.flexGrow = String(Math.max(0.35, part));
      els[i].l.style.flexBasis = "0";
    });
  ensuite(() => set(parts.map(([part]) => part)));
  return { root: h("div", { class: "segments" }, barres, legendes), set };
}

function panneauPc(v) {
  const st = v.status && v.status.active !== false ? v.status : null;
  const panel = h("div", { class: "pc", role: "group", "aria-label": v.device_name });
  sessionPanels.set(v.device_id, panel);

  // Carte bleue : la lune et une phrase qui dit l'essentiel.
  const moon = astre(v.device_name);
  const phrase = h("p", { class: "phrase" });
  const heros = h(
    "article",
    { class: `heros${v.online ? "" : " hors-ligne"}` },
    h(
      "div",
      { class: "haut" },
      h("span", { class: `puce point${v.online ? " vert" : ""}`, text: v.online ? "En ligne" : "Hors ligne" }),
      moon.root,
    ),
    h("div"),
    phrase,
    h("span", { class: "point-ciel" }),
    h("span", { class: "point-ciel" }),
    h("span", { class: "point-ciel" }),
  );

  const carte = h("article", { class: "carte" });
  const graphe = h("article", { class: "carte" });
  const sess = state.config?.config?.session ?? {};
  const cyclesPrevus = sess.mode === "pomodoro" ? sess.cycles ?? 4 : 0;
  const etiquettesCycles = (n) => Array.from({ length: n }, (_, i) => `C${i + 1}`);

  if (!v.online) {
    moon.root.classList.add("hors-ligne", "inactif");
    moon.set(0, "—", "hors ligne", `${v.device_name} : hors ligne`);
    phrase.textContent = `${v.device_name} est hors ligne pour le moment`;
    carte.append(
      h("div", { class: "titre-carte" }, h("h2", { text: "Reconnecter ce PC" }), h("span", { class: "puce douce point", text: "Arrêté" })),
      h("p", { class: "discret", text: "Le connecteur ne tourne pas sur ce PC. Lancez-le dans un terminal, la carte se mettra à jour toute seule :" }),
      commande("cocon agent"),
      h("p", { class: "discret petit", text: "Astuce : activez son service pour qu'il démarre avec l'ordinateur." }),
    );
    const r = rythme(etiquettesCycles(cyclesPrevus || 1));
    r.set(-1, 0);
    graphe.append(h("h2", { text: "Rythme" }), h("p", { class: "discret petit", text: "Dernier rythme enregistré" }), r.root);
  } else if (!st) {
    moon.root.classList.add("inactif");
    const defaut = sess.default_minutes ?? 90;
    moon.set(0, String(defaut), "min prêtes", `${v.device_name} : prêt, aucune session`);
    const dire = (m) => {
      phrase.replaceChildren(`${v.device_name} est prêt pour `, h("span", { class: "chiffres", text: `${m} minutes` }), " de concentration");
    };
    dire(defaut);
    const chiffre = h("div", { class: "grand-chiffre" }, String(defaut), h("small", { text: "min" }));
    const enTete = h("div", { class: "chiffre-et-puce" }, chiffre, h("span", { class: "puce douce", text: "Prêt à démarrer" }));
    const minutes = h("input", { type: "number", min: 1, max: 1440, value: defaut, "aria-label": "Durée en minutes" });
    const erreur = h("p", { class: "erreur", role: "alert" });
    const bouton = h("button", { class: "bouton principal", type: "submit" }, "Démarrer la session");
    minutes.addEventListener("input", () => {
      const m = Number(minutes.value);
      if (m >= 1) {
        moon.set(0, String(m), "min prêtes");
        chiffre.firstChild.textContent = String(m);
        dire(m);
      }
    });
    carte.append(
      h("h2", { text: "Nouvelle session" }),
      enTete,
      h("p", { class: "discret", text: "Les applications non autorisées seront mises en pause pendant la durée choisie." }),
      h(
        "form",
        {
          class: "rangee",
          onsubmit: async (e) => {
            e.preventDefault();
            erreur.textContent = "";
            bouton.disabled = true;
            bouton.textContent = "Démarrage…";
            try {
              await api("POST", "/v1/session/start", { minutes: Number(minutes.value), device_id: v.device_id });
            } catch (err) {
              erreur.textContent = err.message;
              bouton.disabled = false;
              bouton.textContent = "Démarrer la session";
            }
          },
        },
        h("label", { class: "champ" }, "Durée (minutes)", minutes),
        bouton,
      ),
      erreur,
    );
    const r = rythme(cyclesPrevus ? etiquettesCycles(cyclesPrevus) : ["Bloc"]);
    r.set(-1, 0);
    graphe.append(
      h("h2", { text: "Rythme" }),
      h("div", { class: "grand-chiffre" }, String(cyclesPrevus || 1)),
      h("p", { class: "legende-chiffre", text: cyclesPrevus ? `Cycles prévus de ${sess.work_minutes ?? 25} min` : "Bloc continu, sans pause" }),
      r.root,
    );
  } else {
    const pause = /pause/i.test(st.phase);
    if (pause) moon.root.classList.add("pause");
    const at = state.sessions.get(v.device_id)?.at ?? Date.now();
    const sessionLeft = h("span", { text: "" });
    const fin = st.planned_end ? h("span", { class: "puce douce", text: `Fin vers ${heure(st.planned_end)}` }) : null;

    // Barre segmentée : les cycles, sinon les objectifs, sinon la phase.
    const avecCycles = st.cycles > 0;
    const avecObjectifs = !avecCycles && st.goals_total > 0;
    const seg = avecCycles
      ? segments([
          [st.cycle - 1, "bleu", "Cycles faits"],
          [1, "orange", "En cours"],
          [st.cycles - st.cycle, "", "À venir"],
        ])
      : avecObjectifs
      ? segments([
          [st.goals_done, "bleu", `${st.goals_done} atteint${st.goals_done > 1 ? "s" : ""}`],
          [st.goals_total - st.goals_done, "", `${st.goals_total - st.goals_done} à faire`],
        ])
      : segments([
          [0, pause ? "orange" : "bleu", st.phase],
          [1, "", "Reste"],
        ]);

    const puces = h("div", { class: "puces" });
    puces.append(
      h("span", { class: `puce point${st.notifications ? " vert" : ""}`, text: st.notifications ? `Notifications coupées (${st.notifications})` : "Notifications actives" }),
      h("span", { class: `puce point${st.sites_blocked ? " vert" : ""}`, text: st.sites_blocked ? "Sites bloqués" : "Sites non bloqués" }),
      ...(st.paused_apps?.length ? st.paused_apps : []).map((a) => h("span", { class: "puce point orange", text: `${a} en pause` })),
    );

    const erreur = h("p", { class: "erreur", role: "alert" });
    carte.append(
      h("h2", { text: "Session en cours" }),
      h("div", { class: "chiffre-et-puce" }, h("div", { class: "grand-chiffre" }, sessionLeft), fin),
      h("p", { class: "legende-chiffre", text: "restantes sur la session" }),
      seg.root,
      st.goals_total > 0 && avecCycles
        ? h("p", { class: "petit" }, `${st.goals_done} objectif${st.goals_done > 1 ? "s" : ""} atteint${st.goals_done > 1 ? "s" : ""} `, h("span", { class: "discret", text: `sur ${st.goals_total}` }))
        : "",
      h("p", { class: "petit" }, "Pendant la session ", h("span", { class: "discret", text: "sur ce PC :" })),
      puces,
      st.notice ? h("p", { class: "avertissement", text: st.notice }) : "",
      h("div", { class: "rangee" }, h("button", { class: "bouton", type: "button", onclick: () => arreter(v.device_id, erreur) }, "Arrêter la session")),
      erreur,
    );

    const parCycles = st.cycles > 0;
    const r = rythme(parCycles ? etiquettesCycles(st.cycles) : ["10", "20", "30", "40", "50", "60", "70", "80", "90", "100"]);
    const pct = h("span", {});
    graphe.append(
      h("h2", { text: parCycles ? "Cycles" : "Phase" }),
      h("div", { class: "grand-chiffre" }, pct),
      h("p", { class: "legende-chiffre", text: `${parCycles ? `Cycle sur ${st.cycles}` : "De la phase écoulée"} · ${st.paused ? "en pause" : st.phase.toLowerCase()}` }),
      r.root,
    );

    const update = () => {
      const elapsed = st.paused ? 0 : (Date.now() - at) / 1000;
      const left = Math.max(0, st.phase_remaining_secs - elapsed);
      const f = st.phase_len_secs > 0 ? 1 - left / st.phase_len_secs : 0;
      const main = left >= 60 ? String(Math.ceil(left / 60)) : String(Math.ceil(left));
      const unit = left >= 60 ? "min" : "s";
      moon.set(f, main, st.paused ? "en pause" : unit, `${st.phase} : ${duree(left)} restantes`);
      sessionLeft.textContent = duree(Math.max(0, st.session_remaining_secs - elapsed));
      phrase.replaceChildren(
        st.paused ? "Session en pause, " : "Encore ",
        h("span", { class: "chiffres", text: duree(left) }),
        ` de ${st.phase.toLowerCase()} sur ${v.device_name}`,
      );
      if (!avecCycles && !avecObjectifs) seg.set([f, 1 - f]);
      if (parCycles) {
        pct.textContent = `${st.cycle}/${st.cycles}`;
        r.set(st.cycle - 1, f, `${Math.round(f * 100)} %`);
      } else {
        pct.textContent = `${Math.round(f * 100)} %`;
        r.set(Math.min(9, Math.floor(f * 10)), (f * 10) % 1, `${Math.round(f * 100)} %`);
      }
    };
    update();
    ticks.push(update);
  }
  panel.append(heros, carte, graphe);
  return panel;
}

/// Date courte : « 7 nov., 15:20 ».
function jour(iso) {
  const d = new Date(iso);
  return Number.isNaN(d.getTime())
    ? ""
    : `${d.toLocaleDateString("fr-FR", { day: "numeric", month: "short" })}, ${heure(iso)}`;
}

/// Tâches déjà affichées : les nouvelles glissent dans la liste.
const tachesVues = new Set();

/// Prénom deviné depuis l'e-mail (« marie.dupont@… » → « Marie »), ou rien
/// quand la partie locale ne ressemble pas à un prénom.
function prenom(email) {
  const mot = email.split("@")[0].split(/[._+-]/)[0].replace(/\d+/g, "");
  if (mot.length < 2 || mot.length > 12) return "";
  return mot[0].toUpperCase() + mot.slice(1).toLowerCase();
}

/// La liste des tâches, présentée comme un historique : on y ajoute,
/// coche, étoile et supprime sans quitter le tableau de bord.
function carteTaches(ouvert = false) {
  const tasks = state.tasks?.tasks ?? [];
  const open = tasks.filter((t) => !t.done).sort((a, b) => Number(b.for_session) - Number(a.for_session));
  const done = tasks.filter((t) => t.done).sort((a, b) => String(b.done_at).localeCompare(String(a.done_at)));
  const etoilees = open.filter((t) => t.for_session).length;
  const premiere = tachesVues.size === 0;

  const erreur = h("p", { class: "erreur", role: "alert" });
  const apply = async (fn) => {
    erreur.textContent = "";
    try {
      state.tasks = await fn();
      majCartesTaches(false);
    } catch (err) {
      erreur.textContent = err.message;
      if (err.status === 409) majCartesTaches(true);
    }
  };

  const texte = h("input", { type: "text", maxlength: 1000, "aria-label": "Nouvelle tâche", placeholder: "Ajouter une tâche…" });
  let etoilee = false;
  const etoile = h("button", {
    class: "icone",
    type: "button",
    "aria-pressed": "false",
    "aria-label": "En faire un objectif de la prochaine session",
    title: "En faire un objectif de la prochaine session",
  }, "☆");
  etoile.addEventListener("click", () => {
    etoilee = !etoilee;
    etoile.setAttribute("aria-pressed", String(etoilee));
    etoile.textContent = etoilee ? "★" : "☆";
    texte.focus();
  });
  const ajout = h(
    "form",
    {
      class: "rangee ajout",
      onsubmit: (e) => {
        e.preventDefault();
        if (!texte.value.trim()) return;
        const body = { text: texte.value, for_session: etoilee };
        texte.value = "";
        apply(() => api("POST", "/v1/tasks", body));
      },
    },
    h("label", { class: "champ" }, texte),
    etoile,
    h("button", { class: "bouton principal", type: "submit" }, "Ajouter"),
  );

  const ligne = (t) => {
    const nouveau = !premiere && !tachesVues.has(t.id);
    tachesVues.add(t.id);
    const check = h("input", { type: "checkbox", class: "case-ronde", "aria-label": `Terminée : ${t.text}` });
    check.checked = t.done;
    check.addEventListener("change", (e) => {
      const li = e.currentTarget.closest("li");
      li?.classList.toggle("termine", check.checked);
      const envoi = () => apply(() => api("PATCH", `/v1/tasks/${encodeURIComponent(t.id)}`, { done: check.checked }));
      if (check.checked && !sansAnimation) setTimeout(envoi, 700);
      else envoi();
    });
    const star = t.done
      ? h("span")
      : h("button", {
          class: "icone",
          type: "button",
          "aria-pressed": String(t.for_session),
          "aria-label": `Objectif de la prochaine session : ${t.text}`,
          title: t.for_session ? "Retirer des objectifs" : "En faire un objectif de la prochaine session",
          onclick: () => apply(() => api("PATCH", `/v1/tasks/${encodeURIComponent(t.id)}`, { for_session: !t.for_session })),
        }, t.for_session ? "★" : "☆");
    const del = h("button", {
      class: "icone",
      type: "button",
      "aria-label": `Supprimer : ${t.text}`,
      title: "Supprimer",
      onclick: (e) => {
        // La ligne s'efface avant que la liste ne soit redessinée.
        e.currentTarget.closest("li")?.classList.add("sortie");
        setTimeout(() => apply(() => api("DELETE", `/v1/tasks/${encodeURIComponent(t.id)}`)), sansAnimation ? 0 : 220);
      },
    }, "×");
    return h(
      "li",
      { class: `${t.done ? "fait" : ""}${nouveau ? " nouveau" : ""}` },
      check,
      h("span", { class: "texte", text: t.text }),
      h("span", { class: "quand", text: jour(t.done ? t.done_at : t.created) }),
      h("span", { class: `puce point ${t.done ? "vert" : t.for_session ? "orange" : ""}`, text: t.done ? "Terminée" : t.for_session ? "Objectif" : "À faire" }),
      star,
      del,
    );
  };

  return h(
    "article",
    { class: "carte large" },
    h(
      "div",
      { class: "titre-carte" },
      h("div", {}, h("h2", { text: "Tâches" }), h("p", { class: "discret", text: resumeTaches(etoilees, open.length) })),
    ),
    ajout,
    erreur,
    open.length
      ? h("ul", { class: "lignes lignes-taches" }, open.map(ligne))
      : h("p", { class: "discret vide-taches", text: tasks.length ? "Plus rien à faire. Ajoutez la suite quand vous voulez." : "Notez ce que vous voulez accomplir, puis étoilez (☆) ce qui compte pour la prochaine session." }),
    done.length
      ? h(
          "details",
          { class: "bloc-replie", open: ouvert },
          h("summary", { class: "discret", text: `Terminées (${done.length})` }),
          h("ul", { class: "lignes lignes-taches" }, done.map(ligne)),
          h("div", {}, h("button", {
            class: "bouton lien",
            type: "button",
            onclick: () => apply(() => api("PUT", "/v1/tasks", { version: state.tasks.version, tasks: tasks.filter((t) => !t.done) })),
          }, "Effacer les tâches terminées")),
        )
      : "",
  );
}

/// « 2 objectifs pour la prochaine session · 3 à faire », sans « 0 ».
function resumeTaches(etoilees, ouvertes) {
  if (ouvertes === 0) return "Tout est fait. Bravo !";
  const obj = etoilees === 0 ? "Aucun objectif étoilé" : `${etoilees} objectif${etoilees > 1 ? "s" : ""} pour la prochaine session`;
  return `${obj} · ${ouvertes} à faire`;
}

/// Dernières parts affichées, d'où repartent les barres à chaque mise à jour.
const bilanPrecedent = new Map();

/// Répartition des tâches, en barres décroissantes.
function carteBilan() {
  const tasks = state.tasks?.tasks ?? [];
  const total = tasks.length;
  const carte = h("article", { class: "carte" }, h("h2", { text: "Bilan" }));
  if (total === 0) {
    carte.append(h("p", { class: "discret", text: "Le bilan apparaîtra avec vos premières tâches." }));
    return carte;
  }
  const parts = [
    ["Objectifs", tasks.filter((t) => t.for_session && !t.done).length],
    ["À faire", tasks.filter((t) => !t.for_session && !t.done).length],
    ["Terminées", tasks.filter((t) => t.done).length],
  ];
  parts.sort((a, b) => b[1] - a[1]);
  const zone = h("div", { class: "repartition" });
  for (const [label, n] of parts) {
    const pct = Math.round((n / total) * 100);
    const avant = bilanPrecedent.get(label);
    const chiffre = h("span", { class: "chiffres" });
    const barre = h("div", { class: "barre" }, chiffre, h("small", { text: label }));
    barre.style.height = `${Math.max(28, avant ?? 0)}%`;
    ensuite(() => (barre.style.height = `${Math.max(28, pct)}%`));
    compter(chiffre, pct, (x) => `${x} %`, avant ?? 0);
    bilanPrecedent.set(label, pct);
    zone.append(barre);
  }
  // Le repère nomme la plus grande part, seulement s'il passe au-dessus des autres.
  const haut = Math.max(28, Math.round((parts[0][1] / total) * 100));
  const second = Math.max(28, Math.round((parts[1][1] / total) * 100));
  if (haut - second >= 18) {
    const repere = h("div", { class: "repere", "aria-hidden": "true" }, h("span", { text: parts[0][0] }));
    repere.style.bottom = `calc(${haut}% - 44px)`;
    zone.append(repere);
  }
  carte.append(h("p", { class: "discret petit", text: `${total} tâche${total > 1 ? "s" : ""} au total` }), zone);
  return carte;
}

/// Arrêt à distance, en respectant la friction choisie sur le PC.
async function arreter(deviceId, erreur) {
  erreur.textContent = "";
  let confirmation = "";
  try {
    for (let i = 0; i < 3; i++) {
      const out = await api("POST", "/v1/session/stop", { confirmation, device_id: deviceId });
      const reply = out.reply ?? {};
      if (reply.result === "stopped") return;
      if (reply.result === "need_phrase") {
        const p = await demanderPhrase(reply.detail, i > 0);
        if (p == null) return;
        confirmation = p;
      } else if (reply.result === "need_hold") {
        const ok = await demanderMaintien(Number(reply.detail) || 3);
        if (!ok) return;
        confirmation = "maintenu";
      } else {
        return;
      }
    }
  } catch (err) {
    erreur.textContent = err.message;
  }
}

function demanderPhrase(phrase, retry) {
  return dialog((close) => {
    const input = h("input", { type: "text", autocomplete: "off", "aria-label": "Phrase de sortie" });
    queueMicrotask(() => input.focus());
    return h(
      "form",
      { onsubmit: (e) => { e.preventDefault(); close(input.value); } },
      h("h2", { text: "Arrêter la session ?" }),
      retry ? h("p", { class: "erreur", text: "La phrase ne correspond pas." }) : null,
      h("p", { class: "discret" }, "Pour confirmer, tapez : « ", h("strong", { text: phrase }), " »"),
      input,
      h("div", { class: "actions" },
        h("button", { class: "bouton", type: "button", onclick: () => close(null) }, "Continuer la session"),
        h("button", { class: "bouton danger", type: "submit" }, "Arrêter"),
      ),
    );
  });
}

function demanderMaintien(secs) {
  return dialog((close) => {
    const jauge = h("span", { class: "jauge" });
    const btn = h("button", { class: "maintien", type: "button" }, jauge, h("span", { text: `Maintenir ${secs} secondes pour arrêter` }));
    let start = 0;
    let raf = 0;
    const step = () => {
      const p = Math.min(1, (performance.now() - start) / (secs * 1000));
      jauge.style.width = `${p * 100}%`;
      if (p >= 1) close(true);
      else raf = requestAnimationFrame(step);
    };
    const begin = (e) => {
      e.preventDefault();
      if (start) return;
      start = performance.now();
      raf = requestAnimationFrame(step);
    };
    const cancel = () => {
      cancelAnimationFrame(raf);
      start = 0;
      jauge.style.width = "0";
    };
    btn.addEventListener("pointerdown", begin);
    btn.addEventListener("pointerup", cancel);
    btn.addEventListener("pointerleave", cancel);
    btn.addEventListener("keydown", (e) => (e.key === " " || e.key === "Enter") && begin(e));
    btn.addEventListener("keyup", (e) => (e.key === " " || e.key === "Enter") && cancel());
    queueMicrotask(() => btn.focus());
    return h(
      "form",
      { onsubmit: (e) => e.preventDefault() },
      h("h2", { text: "Arrêter la session ?" }),
      h("p", { class: "discret", text: "Gardez le bouton enfoncé (ou la touche Espace) jusqu'au bout." }),
      btn,
      h("div", { class: "actions" }, h("button", { class: "bouton", type: "button", onclick: () => close(false) }, "Continuer la session")),
    );
  });
}

// ------------------------------------------------------------ hydratation
//
// Le serveur décide quand rappeler de boire (réglages, horloge et compteur
// sont les siens) ; cette page affiche le compteur, le rappel, et note les
// prises. Les PC reliés y reportent les leurs (barre de session, fenêtre
// principale, `cocon water`) : le compteur est le même partout.

let carteEauAffichee = null;

/// « 250 ml », « 1,25 L ».
function litres(ml) {
  if (ml < 1000) return `${Math.round(ml)} ml`;
  return `${(ml / 1000).toLocaleString("fr-FR", { maximumFractionDigits: 2 })} L`;
}

/// Une prise (`ml` absent : un verre), ou l'annulation de la dernière.
async function boire(methode = "POST", ml) {
  state.hydration = await api(methode, "/v1/hydration/drink", ml === undefined ? undefined : { ml });
  majCarteEau();
  return state.hydration;
}

function majCarteEau() {
  if (!carteEauAffichee?.isConnected || !state.hydration) return;
  const nouvelle = carteEau();
  carteEauAffichee.replaceWith(nouvelle);
  carteEauAffichee = nouvelle;
}

/// Goutte d'eau : pleine pour un verre bu, en contour sinon.
function goutte(pleine) {
  const g = s("svg", { viewBox: "0 0 24 24", "aria-hidden": "true", class: pleine ? "goutte pleine" : "goutte" });
  g.append(s("path", { d: "M12 2.5c3.2 4.2 6.5 8.1 6.5 11.6A6.5 6.5 0 0 1 5.5 14.1C5.5 10.6 8.8 6.7 12 2.5z" }));
  return g;
}

/// Bouteille proposée en plus du verre.
const BOUTEILLE_ML = 500;

function carteEau() {
  const { settings, today, today_ml, next_reminder } = state.hydration;
  const objectif = settings.goal_ml;
  const erreur = h("p", { class: "erreur", role: "alert" });
  const agir = async (fn) => {
    erreur.textContent = "";
    try {
      await fn();
    } catch (err) {
      erreur.textContent = err.message;
    }
  };
  const prochain = !settings.enabled
    ? "Rappels désactivés"
    : next_reminder
      ? `Prochain rappel à ${heure(next_reminder)}`
      : "Aucun rappel prévu";
  // Une goutte par verre de l'objectif (12 au plus, chacune vaut alors
  // davantage).
  const nb = Math.max(1, Math.min(12, Math.ceil(objectif / settings.glass_ml)));
  const pleines = Math.min(nb, Math.floor((today_ml * nb) / objectif));
  const gouttes = h("div", { class: "gouttes", role: "img", "aria-label": `${litres(today_ml)} sur ${litres(objectif)}` });
  for (let i = 0; i < nb; i++) gouttes.append(goutte(i < pleines));
  if (today_ml > objectif) gouttes.append(h("span", { class: "en-plus", text: `+${litres(today_ml - objectif)}` }));
  const chiffre = h("span", { class: "chiffres" });
  compter(chiffre, today_ml, litres);
  return h(
    "article",
    { class: "carte pleine eau" },
    h("div", { class: "titre-carte" },
      h("div", {}, h("h2", { text: "Hydratation" }), h("p", { class: "discret petit", text: prochain })),
      h("button", { class: "bouton", type: "button", onclick: reglagesEau }, "Réglages"),
    ),
    h("div", { class: "eau-corps" },
      h("p", { class: "grand-chiffre" }, chiffre, h("small", { text: `/ ${litres(objectif)}` })),
      gouttes,
      h("div", { class: "rangee" },
        h("button", { class: "bouton principal", type: "button", onclick: () => agir(() => boire()) }, `Un verre · ${litres(settings.glass_ml)}`),
        h("button", { class: "bouton", type: "button", onclick: () => agir(() => boire("POST", BOUTEILLE_ML)) }, `+ ${litres(BOUTEILLE_ML)}`),
        today > 0
          ? h("button", { class: "bouton lien", type: "button", onclick: () => agir(() => boire("DELETE")) }, "Annuler le dernier")
          : null,
      ),
    ),
    erreur,
  );
}

/// Bandeau de rappel, et notification du navigateur si l'onglet est caché.
let rappel = null;

function fermerRappel() {
  rappel?.remove();
  rappel = null;
}

function afficherRappel(today_ml, goal_ml) {
  fermerRappel();
  const corps =
    today_ml >= goal_ml
      ? `Objectif atteint : ${litres(today_ml)} aujourd'hui.`
      : `${litres(today_ml)} sur ${litres(goal_ml)} aujourd'hui.`;
  const erreur = h("p", { class: "erreur" });
  const bu = h("button", { class: "bouton principal", type: "button" }, "J'ai bu un verre");
  bu.addEventListener("click", async () => {
    bu.disabled = true;
    try {
      await boire();
      fermerRappel();
    } catch (err) {
      erreur.textContent = err.message;
      bu.disabled = false;
    }
  });
  rappel = h(
    "aside",
    { class: "rappel-eau", role: "alert" },
    goutte(true),
    h("div", { class: "texte" }, h("strong", { text: "C'est l'heure de boire un verre d'eau" }), h("span", { class: "discret petit", text: corps }), erreur),
    h("div", { class: "rangee" }, bu, h("button", { class: "bouton lien", type: "button", onclick: fermerRappel }, "Plus tard")),
  );
  document.body.append(rappel);
  if (document.hidden && "Notification" in window && Notification.permission === "granted") {
    const n = new Notification("C'est l'heure de boire un verre d'eau", { body: corps, tag: "cocon-eau", icon: "/icon.svg" });
    n.onclick = () => {
      window.focus();
      n.close();
    };
  }
}

async function reglagesEau() {
  const r = structuredClone(state.hydration.settings);
  // Le fuseau du navigateur fixe l'heure locale des rappels et le début du jour.
  r.timezone = Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC";
  const nombre = (label, key, min, max, step = 1) => {
    const i = h("input", { type: "number", min, max, step, value: r[key], required: true });
    i.addEventListener("input", () => (r[key] = Number(i.value)));
    return h("label", { class: "champ" }, label, i);
  };
  const heureChamp = (label, key) => {
    const i = h("input", { type: "time", value: r[key], required: true });
    i.addEventListener("input", () => (r[key] = i.value));
    return h("label", { class: "champ" }, label, i);
  };
  const actif = h("input", { type: "checkbox" });
  actif.checked = r.enabled;
  actif.addEventListener("change", () => (r.enabled = actif.checked));
  const navigateur =
    "Notification" in window && Notification.permission === "default"
      ? h("button", {
          class: "bouton lien",
          type: "button",
          onclick: async (e) => {
            await Notification.requestPermission();
            e.currentTarget.remove();
          },
        }, "Recevoir aussi les rappels quand cet onglet est en arrière-plan")
      : null;
  await dialog((close) => {
    const erreur = h("p", { class: "erreur", role: "alert" });
    return h("form", {
      onsubmit: async (e) => {
        e.preventDefault();
        erreur.textContent = "";
        try {
          state.hydration = await api("PUT", "/v1/hydration", r);
          majCarteEau();
          close(true);
        } catch (err) {
          erreur.textContent = err.message;
        }
      },
    },
      h("h2", { text: "Rappels d'hydratation" }),
      h("p", { class: "discret", text: `Le serveur vous rappelle de boire sur tous vos appareils : notification sur le PC, bandeau ici. Objectif et verre sont partagés avec vos PC reliés. Heure de ${r.timezone}.` }),
      h("label", { class: "case" }, actif, "Me rappeler de boire"),
      h("div", { class: "grille-champs" },
        nombre("Toutes les (min)", "interval_minutes", 15, 240),
        nombre("Objectif (ml par jour)", "goal_ml", 250, 6000, 50),
        nombre("Contenance d'un verre (ml)", "glass_ml", 50, 1000, 10),
        heureChamp("À partir de", "start"),
        heureChamp("Jusqu'à", "end"),
      ),
      navigateur,
      erreur,
      h("div", { class: "actions" },
        h("button", { class: "bouton", type: "button", onclick: () => close(null) }, "Annuler"),
        h("button", { class: "bouton principal", type: "submit" }, "Enregistrer"),
      ),
    );
  }, "eau");
}

// ------------------------------------------------------------ réglages

/// Les réglages s'ouvrent par-dessus le tableau de bord.
async function ouvrirReglages() {
  try {
    state.config = await api("GET", "/v1/config");
  } catch {
    state.config ??= { version: 0, config: null };
  }
  if (!state.config?.config) {
    await dialog((close) =>
      h("form", { onsubmit: (e) => { e.preventDefault(); close(null); } },
        h("h2", { text: "Reliez d'abord un PC" }),
        h("p", { class: "discret", text: "Les réglages (durée, rythme Pomodoro, sites bloqués…) vivent sur votre ordinateur. Dès qu'il est relié, vous pourrez les modifier ici." }),
        h("div", { class: "actions" }, h("button", { class: "bouton principal", type: "submit" }, "Compris")),
      ));
    return;
  }
  let rouvrir = false;
  await dialog((close) => {
    const col = h("div", { class: "grille-cartes" });
    const fermer = h("button", { class: "icone", type: "button", "aria-label": "Fermer", onclick: () => close(null) }, "×");
    const racine = h(
      "div",
      { class: "reglages" },
      h("div", { class: "titre-carte" },
        h("div", {}, h("h2", { text: "Réglages" }), h("p", { class: "discret", text: "Les mêmes réglages que sur votre PC ; ils s'y appliquent dès l'enregistrement." })),
        fermer),
      col,
    );
    remplirReglages(col, close, () => (rouvrir = true));
    return racine;
  }, "large");
  if (rouvrir) ouvrirReglages();
}

function remplirReglages(col, close, rouvrir) {
  if (!state.config?.config) {
    col.append(h("div", { class: "panneau vide pleine" }, h("p", { text: "Les réglages apparaîtront dès qu'un PC aura été relié à votre compte." })));
    return;
  }
  const c = structuredClone(state.config.config);
  c.session ??= {};
  c.apps ??= { allowed: [] };
  c.web ??= { block: true, sites: [] };
  c.notifications ??= { block: true };

  const nombre = (label, obj, key, min, max) => {
    const i = h("input", { type: "number", min, max, value: obj[key] ?? min });
    i.addEventListener("input", () => (obj[key] = Number(i.value)));
    return h("label", { class: "champ" }, label, i);
  };
  const choix = (label, obj, key, options, onchange) => {
    const sel = h("select", {}, options.map(([v, t]) => h("option", { value: v, selected: obj[key] === v }, t)));
    sel.addEventListener("change", () => {
      obj[key] = sel.value;
      onchange?.();
    });
    return h("label", { class: "champ" }, label, sel);
  };
  const case_ = (label, obj, key, onchange) => {
    const i = h("input", { type: "checkbox" });
    i.checked = !!obj[key];
    i.addEventListener("change", () => {
      obj[key] = i.checked;
      onchange?.();
    });
    return h("label", { class: "case" }, i, label);
  };

  // Session
  const pomodoro = h("div", { class: "grille-champs" },
    nombre("Travail (min)", c.session, "work_minutes", 1, 240),
    nombre("Pause courte (min)", c.session, "short_break_minutes", 1, 60),
    nombre("Pause longue (min)", c.session, "long_break_minutes", 1, 120),
    nombre("Cycles", c.session, "cycles", 1, 12),
  );
  const phrase = h("input", { type: "text", value: c.session.exit_phrase ?? "", maxlength: 200 });
  phrase.addEventListener("input", () => (c.session.exit_phrase = phrase.value));
  const phraseField = h("label", { class: "champ" }, "Phrase à taper", phrase);
  const majSession = () => {
    pomodoro.hidden = c.session.mode !== "pomodoro";
    phraseField.hidden = c.session.exit_friction !== "phrase";
  };
  col.append(
    h("section", { class: "bloc pleine" },
      h("h2", { text: "Session" }),
      h("div", { class: "grille-champs" },
        nombre("Durée par défaut (min)", c.session, "default_minutes", 1, 1440),
        choix("Rythme", c.session, "mode", [["pomodoro", "Pomodoro"], ["fixed", "Durée fixe"]], majSession),
        choix("À la fin", c.session, "on_end", [["ask", "Demander"], ["stop", "Arrêter"]]),
        choix("Pour quitter", c.session, "exit_friction", [["hold", "Maintenir 3 s"], ["phrase", "Taper une phrase"], ["none", "Un clic"]], majSession),
      ),
      pomodoro,
      phraseField,
    ),
  );
  majSession();

  // Sites
  const sites = h("ul", { class: "liste panneau" });
  const dessineSites = () => {
    sites.replaceChildren(
      ...(c.web.sites.length
        ? c.web.sites.map((site, i) =>
            h("li", {}, h("span", { class: "texte", text: site }),
              h("button", { class: "icone", type: "button", "aria-label": `Débloquer ${site}`, onclick: () => { c.web.sites.splice(i, 1); dessineSites(); } }, "×")))
        : [h("li", { class: "discret", text: "Aucun site bloqué." })]),
    );
  };
  const nouveau = h("input", { type: "text", placeholder: "youtube.com", "aria-label": "Site à bloquer", maxlength: 253 });
  dessineSites();
  col.append(
    h("section", { class: "bloc" },
      h("h2", { text: "Sites bloqués" }),
      case_("Bloquer ces sites pendant la session", c.web, "block"),
      sites,
      h("form", {
        class: "rangee",
        onsubmit: (e) => {
          e.preventDefault();
          const d = nouveau.value.trim().toLowerCase().replace(/^https?:\/\//, "").replace(/^www\./, "").split("/")[0];
          if (/^[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(d) && !c.web.sites.includes(d)) {
            c.web.sites.push(d);
            dessineSites();
          }
          nouveau.value = "";
        },
      }, h("label", { class: "champ" }, "Ajouter un site", nouveau), h("button", { class: "bouton", type: "submit" }, "Ajouter")),
    ),
  );

  // Notifications et applications
  const apps = h("ul", { class: "liste panneau" });
  const dessineApps = () => {
    apps.replaceChildren(
      ...(c.apps.allowed.length
        ? c.apps.allowed.map((id, i) =>
            h("li", {}, h("span", { class: "texte", text: id }),
              h("button", { class: "icone", type: "button", "aria-label": `Retirer ${id}`, onclick: () => { c.apps.allowed.splice(i, 1); dessineApps(); } }, "×")))
        : [h("li", { class: "discret", text: "Aucune application autorisée." })]),
    );
  };
  dessineApps();
  col.append(
    h("section", { class: "bloc" }, h("h2", { text: "Notifications" }), case_("Couper les notifications pendant la session", c.notifications, "block")),
    h("section", { class: "bloc" },
      h("h2", { text: "Applications autorisées" }),
      h("p", { class: "discret petit", text: "Pour en ajouter, utilisez Cocon sur votre PC : il connaît les applications installées." }),
      apps,
    ),
  );

  // Enregistrement
  const message = h("p", { class: "ok", role: "status" });
  const erreur = h("p", { class: "erreur", role: "alert" });
  const save = h("button", { class: "bouton principal", type: "button" }, "Enregistrer");
  save.addEventListener("click", async () => {
    message.textContent = erreur.textContent = "";
    save.disabled = true;
    try {
      state.config = await api("PUT", "/v1/config", { version: state.config.version, config: c });
      message.textContent = "Réglages enregistrés.";
      majReglagesAffiches();
      setTimeout(() => close(true), sansAnimation ? 0 : 700);
    } catch (err) {
      if (err.status === 409) {
        erreur.textContent = "Ces réglages ont changé ailleurs entre-temps. La version à jour va s'afficher : refaites votre modification.";
        setTimeout(() => {
          rouvrir();
          close(null);
        }, 2500);
      } else {
        erreur.textContent = err.message;
      }
    } finally {
      save.disabled = false;
    }
  });
  col.append(h("div", { class: "rangee pleine" }, h("button", { class: "bouton", type: "button", onclick: () => close(null) }, "Annuler"), save, message, erreur));
}

// ------------------------------------------------------------ appareils (page Sécurité)

/// Emplacement de la carte des appareils, redessinée en direct.
let emplacementAppareils = null;

async function majAppareils() {
  if (!emplacementAppareils?.isConnected) return;
  const col = h("div", { class: "pleine appareils" });
  await carteAppareils(col);
  emplacementAppareils.replaceWith(col);
  emplacementAppareils = col;
}

async function carteAppareils(col) {
  const erreur = h("p", { class: "erreur", role: "alert" });
  try {
    state.devices = await api("GET", "/v1/devices");
  } catch (err) {
    col.append(h("p", { class: "erreur", text: err.message }));
    return;
  }
  const genre = { desktop: "Ordinateur", mobile: "Application mobile", web: "Navigateur" };
  const teinte = { desktop: "bleu", mobile: "orange", web: "" };
  col.append(
    h("article", { class: "carte" },
      h("div", {}, h("h2", { text: "Appareils connectés" }), h("p", { class: "discret", text: `${state.devices.length} appareil${state.devices.length > 1 ? "s" : ""} relié${state.devices.length > 1 ? "s" : ""} à votre compte. Révoquez ce que vous ne reconnaissez pas.` })),
      h("ul", { class: "lignes lignes-appareils" },
        state.devices.map((d) =>
          h("li", {},
            h("span", { class: `initiale ${teinte[d.kind] ?? "clair"}`, "aria-hidden": "true", text: d.name.trim().slice(0, 1) || "·" }),
            h("div", { class: "texte" },
              h("div", {}, d.name, d.current ? h("span", { class: "discret", text: " · cet appareil" }) : null),
              h("div", { class: "discret petit", text: genre[d.kind] ?? d.kind }),
            ),
            h("span", { class: "quand", text: d.kind === "desktop" ? "" : `vu ${quand(d.last_seen)}` }),
            d.kind === "desktop"
              ? h("span", { class: `puce point${d.online ? " vert" : ""}`, text: d.online ? "Connecté" : "Déconnecté" })
              : h("span", { class: `puce point${d.current ? " vert" : ""}`, text: d.current ? "Vous êtes ici" : "Session web" }),
            d.current
              ? h("button", {
                  class: "bouton",
                  type: "button",
                  onclick: async () => {
                    try {
                      await api("POST", "/web/logout");
                    } finally {
                      leave();
                    }
                  },
                }, "Se déconnecter")
              : h("button", {
              class: "bouton danger",
              type: "button",
              onclick: async () => {
                const ok = await dialog((close) =>
                  h("form", { onsubmit: (e) => { e.preventDefault(); close(true); } },
                    h("h2", { text: "Révoquer cet appareil ?" }),
                    h("p", { class: "discret", text: `« ${d.name} » devra se reconnecter avec votre mot de passe.` }),
                    h("div", { class: "actions" },
                      h("button", { class: "bouton", type: "button", onclick: () => close(false) }, "Annuler"),
                      h("button", { class: "bouton danger", type: "submit" }, "Révoquer")),
                  ));
                if (!ok) return;
                try {
                  await api("DELETE", `/v1/devices/${encodeURIComponent(d.id)}`);
                  majAppareils();
                } catch (err) {
                  erreur.textContent = err.message;
                }
              },
            }, "Révoquer"),
          ),
        ),
      ),
      erreur,
    ),
  );
}

// ------------------------------------------------------------ sécurité

function vueSecurite(view) {
  entete(view, "Sécurité", `Compte ${state.me.email}`);
  const col = h("div", { class: "grille-cartes une" });
  view.append(col);

  // Mot de passe
  const actuel = h("input", { type: "password", autocomplete: "current-password", required: true });
  const nouveau = h("input", { type: "password", autocomplete: "new-password", minlength: 12, required: true });
  const encore = h("input", { type: "password", autocomplete: "new-password", minlength: 12, required: true });
  const pwOk = h("p", { class: "ok", role: "status" });
  const pwErr = h("p", { class: "erreur", role: "alert" });
  col.append(
    h("section", { class: "bloc" },
      h("div", {}, h("h2", { text: "Mot de passe" }), h("p", { class: "discret", text: "Changer de mot de passe déconnecte vos autres appareils." })),
      h("form", {
        class: "formulaire-ligne",
        onsubmit: async (e) => {
          e.preventDefault();
          pwOk.textContent = pwErr.textContent = "";
          if (nouveau.value !== encore.value) {
            pwErr.textContent = "Les deux nouveaux mots de passe diffèrent.";
            return;
          }
          try {
            await api("POST", "/web/password", { current: actuel.value, new: nouveau.value });
            actuel.value = nouveau.value = encore.value = "";
            pwOk.textContent = "Mot de passe changé. Vos autres appareils devront se reconnecter.";
          } catch (err) {
            pwErr.textContent = err.message;
          }
        },
      },
        h("label", { class: "champ" }, "Mot de passe actuel", actuel),
        h("label", { class: "champ" }, "Nouveau (12 caractères au moins)", nouveau),
        h("label", { class: "champ" }, "Confirmer le nouveau", encore),
        pwOk, pwErr,
        h("div", {}, h("button", { class: "bouton principal", type: "submit" }, "Changer le mot de passe")),
      ),
    ),
  );

  // Double authentification
  const totpZone = h("section", { class: "bloc" });
  const appareils = h("div", { class: "pleine appareils" });
  emplacementAppareils = appareils;
  carteAppareils(appareils);
  const dessineTotp = () => {
    const err = h("p", { class: "erreur", role: "alert" });
    if (state.me.totp_enabled) {
      const pw = h("input", { type: "password", autocomplete: "current-password", required: true });
      const code = h("input", { type: "text", inputmode: "numeric", autocomplete: "one-time-code", required: true, maxlength: 8 });
      totpZone.replaceChildren(
        h("h2", { text: "Double authentification" }),
        h("p", { class: "ok", text: "Active : un code de votre application est demandé à chaque connexion." }),
        h("details", {},
          h("summary", { class: "discret", text: "Désactiver" }),
          h("form", {
            class: "colonne",
            onsubmit: async (e) => {
              e.preventDefault();
              try {
                await api("POST", "/web/totp/disable", { password: pw.value, code: code.value });
                state.me.totp_enabled = false;
                dessineTotp();
              } catch (x) {
                err.textContent = x.message;
              }
            },
          },
            h("label", { class: "champ" }, "Mot de passe", pw),
            h("label", { class: "champ" }, "Code actuel", code),
            err,
            h("div", {}, h("button", { class: "bouton danger", type: "submit" }, "Désactiver la double authentification")),
          ),
        ),
      );
    } else {
      totpZone.replaceChildren(
        h("h2", { text: "Double authentification" }),
        h("p", { class: "discret", text: "Recommandée : même avec votre mot de passe, personne ne pourra piloter vos sessions sans votre téléphone." }),
        h("div", {}, h("button", { class: "bouton principal", type: "button", onclick: activerTotp }, "Activer")),
      );
    }
  };
  const activerTotp = async () => {
    const done = await dialog((close) => {
      const pw = h("input", { type: "password", autocomplete: "current-password", required: true });
      const err = h("p", { class: "erreur", role: "alert" });
      const form = h("form", {
        onsubmit: async (e) => {
          e.preventDefault();
          err.textContent = "";
          try {
            const setup = await api("POST", "/web/totp/setup", { password: pw.value });
            const code = h("input", { type: "text", inputmode: "numeric", autocomplete: "one-time-code", required: true, maxlength: 8 });
            const err2 = h("p", { class: "erreur", role: "alert" });
            form.replaceWith(
              h("form", {
                onsubmit: async (ev) => {
                  ev.preventDefault();
                  try {
                    await api("POST", "/web/totp/confirm", { code: code.value });
                    close(true);
                  } catch (x) {
                    err2.textContent = x.message;
                  }
                },
              },
                h("h2", { text: "Scannez ce code" }),
                h("p", { class: "discret petit", text: "Avec Aegis, Google Authenticator ou une application équivalente." }),
                h("img", { class: "qr", src: `data:image/png;base64,${setup.qr_png}`, alt: "QR code de double authentification" }),
                h("p", { class: "discret petit" }, "Ou saisissez la clé : ", h("code", { text: setup.secret })),
                h("label", { class: "champ" }, "Code affiché", code),
                err2,
                h("div", { class: "actions" },
                  h("button", { class: "bouton", type: "button", onclick: () => close(false) }, "Annuler"),
                  h("button", { class: "bouton principal", type: "submit" }, "Activer")),
              ),
            );
          } catch (x) {
            err.textContent = x.message;
          }
        },
      },
        h("h2", { text: "Activer la double authentification" }),
        h("label", { class: "champ" }, "Confirmez votre mot de passe", pw),
        err,
        h("div", { class: "actions" },
          h("button", { class: "bouton", type: "button", onclick: () => close(false) }, "Annuler"),
          h("button", { class: "bouton principal", type: "submit" }, "Continuer")),
      );
      queueMicrotask(() => pw.focus());
      return form;
    });
    if (done) {
      state.me.totp_enabled = true;
      dessineTotp();
    }
  };
  dessineTotp();
  col.append(totpZone, appareils);

  // Suppression du compte
  col.append(
    h("section", { class: "bloc pleine zone-danger" },
      h("h2", { text: "Supprimer le compte" }),
      h("p", { class: "discret", text: "Efface définitivement votre compte, vos réglages et vos tâches sur ce serveur, et déconnecte tous vos appareils. Les données de vos PC restent sur vos PC." }),
      h("div", {}, h("button", {
        class: "bouton danger",
        type: "button",
        onclick: async () => {
          await dialog((close) => {
            const pw = h("input", { type: "password", autocomplete: "current-password", required: true });
            const err = h("p", { class: "erreur", role: "alert" });
            return h("form", {
              onsubmit: async (e) => {
                e.preventDefault();
                try {
                  await api("POST", "/web/account/delete", { password: pw.value });
                  close(true);
                  leave();
                } catch (x) {
                  err.textContent = x.message;
                }
              },
            },
              h("h2", { text: "Supprimer définitivement ?" }),
              h("label", { class: "champ" }, "Mot de passe", pw),
              err,
              h("div", { class: "actions" },
                h("button", { class: "bouton", type: "button", onclick: () => close(false) }, "Garder mon compte"),
                h("button", { class: "bouton danger", type: "submit" }, "Supprimer le compte")),
            );
          });
        },
      }, "Supprimer mon compte")),
    ),
  );
}

boot();
