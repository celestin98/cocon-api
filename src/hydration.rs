//! Rappels d'hydratation.
//!
//! C'est le serveur qui décide quand rappeler de boire un verre d'eau, puis
//! qui prévient tous les appareils du compte : connecteur du PC
//! (notification), interface web, application mobile. Réglages, compteur du
//! jour et horloge des rappels vivent ici et non sur les appareils : le
//! rythme est le même partout, que le PC soit allumé ou non.
//!
//! Les prises sont comptées en millilitres et portent un identifiant : le
//! connecteur du PC envoie celles notées hors ligne (barre de session,
//! `cocon water`) et recopie celles notées ailleurs, sans doublon.
//!
//! Règle des rappels : un rappel tombe `interval` minutes après le dernier
//! rappel ou le dernier verre bu (le plus récent des deux), jamais en dehors
//! de la plage horaire choisie ; le premier de la journée tombe `interval`
//! minutes après l'ouverture de la plage.

use std::time::Duration;

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use chrono::{DateTime, Days, NaiveDate, NaiveTime, TimeZone, Utc};
use chrono_tz::Tz;
use serde::{Deserialize, Serialize};

use crate::db;
use crate::protocol::{ClientEvent, Drink, ServerMessage};
use crate::routes::{ApiResult, AppState, Auth, Error};

pub const MIN_INTERVAL: u32 = 15;
pub const MAX_INTERVAL: u32 = 240;
pub const MIN_GOAL_ML: u32 = 250;
pub const MAX_GOAL_ML: u32 = 6000;
pub const MIN_GLASS_ML: u32 = 50;
pub const MAX_GLASS_ML: u32 = 1000;
/// Quantité maximale d'une prise (même borne que le PC).
pub const MAX_DRINK_ML: u32 = 2000;
/// Prises enregistrables par jour (garde-fou contre les clics en rafale).
pub const MAX_DRINKS_PER_DAY: u32 = 60;
/// Jours échangés avec le connecteur (la page du PC en montre 7).
pub const SYNC_DAYS: i64 = 8;
/// Prises acceptées par message du connecteur.
pub const MAX_SYNC_ENTRIES: usize = 200;
/// Historique des verres conservé.
pub const LOG_RETENTION_DAYS: i64 = 90;
/// Fréquence de vérification des rappels dus.
const TICK: Duration = Duration::from_secs(20);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HydrationSettings {
    pub enabled: bool,
    /// Minutes entre deux rappels.
    pub interval_minutes: u32,
    /// Plage des rappels, heure locale « HH:MM » (une fin plus tôt que le
    /// début traverse minuit).
    pub start: String,
    pub end: String,
    /// Objectif du jour, en ml (0 à la lecture d'anciens réglages : voir
    /// [`HydrationSettings::upgrade`]).
    #[serde(default)]
    pub goal_ml: u32,
    /// Contenance d'un verre (bouton « J'ai bu un verre »).
    #[serde(default = "default_glass_ml")]
    pub glass_ml: u32,
    /// Ancien objectif en verres : converti par [`HydrationSettings::upgrade`],
    /// jamais réécrit.
    #[serde(default, skip_serializing)]
    pub goal: Option<u32>,
    /// Fuseau IANA (« Europe/Paris ») : heure locale et début du jour.
    pub timezone: String,
}

impl Default for HydrationSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            interval_minutes: 45,
            start: "09:00".into(),
            end: "21:00".into(),
            goal_ml: 2000,
            glass_ml: default_glass_ml(),
            goal: None,
            timezone: "UTC".into(),
        }
    }
}

fn default_glass_ml() -> u32 {
    250
}

fn parse_time(s: &str) -> Option<NaiveTime> {
    NaiveTime::parse_from_str(s, "%H:%M").ok()
}

impl HydrationSettings {
    /// Anciens réglages (objectif en verres) : objectif converti en ml.
    pub fn upgrade(mut self) -> Self {
        let legacy = self.goal.take();
        if self.goal_ml == 0 {
            self.goal_ml = legacy.map_or(2000, |g| {
                g.saturating_mul(self.glass_ml).clamp(MIN_GOAL_ML, MAX_GOAL_ML)
            });
        }
        self
    }

    /// Objectif exprimé en verres (arrondi au-dessus), pour l'affichage.
    pub fn goal_glasses(&self) -> u32 {
        self.goal_ml.div_ceil(self.glass_ml.max(1))
    }

    pub fn validate(&self) -> Result<(), String> {
        if !(MIN_INTERVAL..=MAX_INTERVAL).contains(&self.interval_minutes) {
            return Err(format!(
                "intervalle entre {MIN_INTERVAL} et {MAX_INTERVAL} minutes"
            ));
        }
        if !(MIN_GOAL_ML..=MAX_GOAL_ML).contains(&self.goal_ml) {
            return Err(format!("objectif entre {MIN_GOAL_ML} et {MAX_GOAL_ML} ml"));
        }
        if !(MIN_GLASS_ML..=MAX_GLASS_ML).contains(&self.glass_ml) {
            return Err(format!("verre entre {MIN_GLASS_ML} et {MAX_GLASS_ML} ml"));
        }
        let (Some(start), Some(end)) = (parse_time(&self.start), parse_time(&self.end)) else {
            return Err("heures au format HH:MM".into());
        };
        if start == end {
            return Err("la plage horaire est vide".into());
        }
        if self.timezone.len() > 64 || self.timezone.parse::<Tz>().is_err() {
            return Err("fuseau horaire inconnu".into());
        }
        Ok(())
    }

    fn tz(&self) -> Tz {
        self.timezone.parse().unwrap_or(Tz::UTC)
    }
}

/// Ce que voient les clients.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HydrationState {
    pub settings: HydrationSettings,
    /// Prises depuis minuit (heure locale).
    pub today: u32,
    /// Quantité bue depuis minuit, en ml.
    pub today_ml: u32,
    pub last_drink: Option<DateTime<Utc>>,
    /// Prochain rappel prévu (`None` : rappels désactivés).
    pub next_reminder: Option<DateTime<Utc>>,
    /// Réglages choisis par l'utilisateur (sinon : valeurs par défaut, que
    /// le premier PC relié peut remplacer par les siennes).
    pub configured: bool,
}

// ------------------------------------------------------------ calendrier

/// Heure locale → instant ; en cas de trou (passage à l'heure d'été),
/// l'heure qui suit.
fn local_to_utc(tz: Tz, date: NaiveDate, time: NaiveTime) -> DateTime<Utc> {
    let naive = date.and_time(time);
    match tz.from_local_datetime(&naive).earliest() {
        Some(t) => t.with_timezone(&Utc),
        None => tz
            .from_local_datetime(&(naive + chrono::Duration::hours(1)))
            .earliest()
            .map(|t| t.with_timezone(&Utc))
            .unwrap_or_else(|| naive.and_utc()),
    }
}

/// Minuit (heure locale) du jour de `now`.
pub fn day_start(s: &HydrationSettings, now: DateTime<Utc>) -> DateTime<Utc> {
    let tz = s.tz();
    local_to_utc(tz, now.with_timezone(&tz).date_naive(), NaiveTime::MIN)
}

/// Prochain rappel après `last` (dernier rappel ou dernier verre). Peut
/// être dans le passé : le rappel est alors dû.
pub fn next_reminder(
    s: &HydrationSettings,
    last: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
) -> Option<DateTime<Utc>> {
    if !s.enabled || s.validate().is_err() {
        return None;
    }
    let tz = s.tz();
    let (start, end) = (parse_time(&s.start)?, parse_time(&s.end)?);
    let interval = chrono::Duration::minutes(s.interval_minutes.into());
    let today = now.with_timezone(&tz).date_naive();
    // La plage de la veille peut encore être ouverte (plage de nuit).
    for offset in -1i64..=2 {
        let date = if offset < 0 {
            today.checked_sub_days(Days::new(1))?
        } else {
            today.checked_add_days(Days::new(offset as u64))?
        };
        let open = local_to_utc(tz, date, start);
        let close_date = if end <= start {
            date.checked_add_days(Days::new(1))?
        } else {
            date
        };
        let close = local_to_utc(tz, close_date, end);
        if close <= now {
            continue;
        }
        let at = last.map_or(open, |l| l.max(open)) + interval;
        if at < close {
            return Some(at);
        }
    }
    None
}

// ------------------------------------------------------------ état

struct Stored {
    settings: HydrationSettings,
    last_reminder: Option<DateTime<Utc>>,
    last_drink: Option<DateTime<Utc>>,
    configured: bool,
}

fn parse_settings(text: &str) -> HydrationSettings {
    serde_json::from_str::<HydrationSettings>(text)
        .unwrap_or_default()
        .upgrade()
}

async fn load(state: &AppState, user: i64) -> ApiResult<Stored> {
    Ok(match db::hydration(&state.db, user).await? {
        Some(row) => Stored {
            settings: parse_settings(&row.settings),
            last_reminder: row.last_reminder,
            last_drink: row.last_drink,
            configured: row.configured,
        },
        None => Stored {
            settings: HydrationSettings::default(),
            last_reminder: None,
            last_drink: None,
            configured: false,
        },
    })
}

pub async fn read(state: &AppState, user: i64) -> ApiResult<HydrationState> {
    let st = load(state, user).await?;
    let now = Utc::now();
    let (today, today_ml) = db::drinks_since(&state.db, user, day_start(&st.settings, now)).await?;
    let next = next_reminder(&st.settings, st.last_reminder.max(st.last_drink), now).map(|t| t.max(now));
    Ok(HydrationState {
        settings: st.settings,
        today,
        today_ml,
        last_drink: st.last_drink,
        next_reminder: next,
        configured: st.configured,
    })
}

/// Ce que le connecteur doit savoir : réglages et prises récentes.
pub async fn snapshot(state: &AppState, user: i64) -> ApiResult<ServerMessage> {
    let st = load(state, user).await?;
    let since = Utc::now() - chrono::Duration::days(SYNC_DAYS);
    Ok(ServerMessage::HydrationSync {
        since,
        entries: db::drinks_after(&state.db, user, since).await?,
        settings: st.settings,
        configured: st.configured,
    })
}

/// État publié à tous les clients (web et connecteurs) après un changement.
async fn changed(state: &AppState, user: i64) -> ApiResult<HydrationState> {
    let s = read(state, user).await?;
    state
        .hub
        .publish(user, ClientEvent::HydrationChanged(Box::new(s.clone())));
    let snap = snapshot(state, user).await?;
    state.hub.broadcast_agents(user, &snap, None);
    Ok(s)
}

/// Une prise venue d'un appareil. `None` : refusée (limite du jour) ou
/// déjà connue (même identifiant).
async fn insert(
    state: &AppState,
    user: i64,
    device: &str,
    settings: &HydrationSettings,
    d: &Drink,
) -> ApiResult<bool> {
    let defaults = serde_json::to_string(settings).map_err(anyhow::Error::from)?;
    Ok(db::add_drink(
        &state.db,
        user,
        device,
        d,
        day_start(settings, d.at),
        MAX_DRINKS_PER_DAY,
        &defaults,
    )
    .await?)
}

/// Une prise maintenant (depuis n'importe quel appareil), d'un verre par
/// défaut. Les rappels encore affichés ailleurs sont retirés.
pub async fn drink(state: &AppState, user: i64, device: &str, ml: Option<u32>) -> ApiResult<HydrationState> {
    let st = load(state, user).await?;
    let ml = ml.unwrap_or(st.settings.glass_ml);
    if !(1..=MAX_DRINK_ML).contains(&ml) {
        return Err(Error::bad_request(format!(
            "quantité entre 1 et {MAX_DRINK_ML} ml"
        )));
    }
    let d = Drink {
        id: new_id(),
        at: Utc::now(),
        ml,
    };
    if !insert(state, user, device, &st.settings, &d).await? {
        return Err(Error::new(
            StatusCode::TOO_MANY_REQUESTS,
            "limit",
            format!("Au plus {MAX_DRINKS_PER_DAY} prises par jour"),
        ));
    }
    state
        .hub
        .broadcast_agents(user, &ServerMessage::HydrationAcknowledged, None);
    changed(state, user).await
}

fn new_id() -> String {
    let mut b = [0u8; 12];
    rand::fill(&mut b[..]);
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Prises notées ou annulées sur un PC (souvent hors ligne). Les prises
/// déjà connues sont ignorées : renvoyer deux fois ne double rien. Renvoie
/// l'état à transmettre au connecteur s'il n'a rien changé (sinon, il le
/// reçoit avec tous les autres).
pub async fn sync(
    state: &AppState,
    user: i64,
    device: &str,
    entries: Vec<Drink>,
    removed: Vec<String>,
) -> ApiResult<Option<ServerMessage>> {
    let now = Utc::now();
    let since = now - chrono::Duration::days(SYNC_DAYS);
    let st = load(state, user).await?;
    let mut added = false;
    let mut recent = false;
    for d in entries.iter().take(MAX_SYNC_ENTRIES) {
        // Hors fenêtre, dans le futur, ou douteuse : ignorée.
        if !valid_id(&d.id)
            || !(1..=MAX_DRINK_ML).contains(&d.ml)
            || d.at < since
            || d.at > now + chrono::Duration::minutes(5)
        {
            continue;
        }
        if insert(state, user, device, &st.settings, d).await? {
            added = true;
            recent |= now - d.at < chrono::Duration::minutes(st.settings.interval_minutes.into());
        }
    }
    let removed: Vec<String> = removed
        .into_iter()
        .filter(|id| valid_id(id))
        .take(MAX_SYNC_ENTRIES)
        .collect();
    let deleted = !removed.is_empty() && db::remove_drinks(&state.db, user, &removed).await? > 0;
    if recent {
        // Un verre vient d'être bu : le rappel affiché a eu sa réponse.
        state
            .hub
            .broadcast_agents(user, &ServerMessage::HydrationAcknowledged, None);
    }
    if added || deleted {
        changed(state, user).await?;
        return Ok(None);
    }
    Ok(Some(snapshot(state, user).await?))
}

/// Réglages modifiés sur un PC. Plage horaire et fuseau restent ceux du
/// serveur, sauf s'il n'a encore que ses valeurs par défaut.
pub async fn settings_from_agent(
    state: &AppState,
    user: i64,
    from_pc: crate::protocol::AgentHydrationSettings,
) -> ApiResult<Option<ServerMessage>> {
    let st = load(state, user).await?;
    let mut next = st.settings.clone();
    next.enabled = from_pc.enabled;
    next.interval_minutes = from_pc.interval_minutes;
    next.goal_ml = from_pc.goal_ml;
    next.glass_ml = from_pc.glass_ml;
    if !st.configured
        && let Some(tz) = from_pc.timezone
    {
        next.timezone = tz;
    }
    if next.validate().is_err() || next == st.settings && st.configured {
        // Refusé ou inchangé : le PC se réaligne sur le serveur.
        return Ok(Some(snapshot(state, user).await?));
    }
    store(state, user, &next).await?;
    Ok(None)
}

async fn store(state: &AppState, user: i64, settings: &HydrationSettings) -> ApiResult<HydrationState> {
    let body = serde_json::to_string(settings).map_err(anyhow::Error::from)?;
    // Nouveau rythme : l'horloge repart de maintenant.
    db::put_hydration(&state.db, user, &body, settings.enabled).await?;
    changed(state, user).await
}

// ------------------------------------------------------------ routes

pub async fn get(State(state): State<AppState>, Auth(a): Auth) -> ApiResult<Json<HydrationState>> {
    Ok(Json(read(&state, a.user_id).await?))
}

pub async fn put(
    State(state): State<AppState>,
    Auth(a): Auth,
    Json(settings): Json<HydrationSettings>,
) -> ApiResult<Json<HydrationState>> {
    let settings = settings.upgrade();
    settings.validate().map_err(Error::bad_request)?;
    Ok(Json(store(&state, a.user_id, &settings).await?))
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DrinkRequest {
    /// Quantité ; un verre (réglages) si absente.
    #[serde(default)]
    pub ml: Option<u32>,
}

/// Corps facultatif : `{"ml": 500}`, ou rien pour un verre.
pub async fn post_drink(
    State(state): State<AppState>,
    Auth(a): Auth,
    body: axum::body::Bytes,
) -> ApiResult<Json<HydrationState>> {
    let req: DrinkRequest = if body.iter().all(u8::is_ascii_whitespace) {
        DrinkRequest::default()
    } else {
        serde_json::from_slice(&body).map_err(|e| Error::bad_request(format!("requête invalide : {e}")))?
    };
    Ok(Json(drink(&state, a.user_id, &a.device_id, req.ml).await?))
}

/// Annule le dernier verre du jour (clic par erreur).
pub async fn delete_drink(State(state): State<AppState>, Auth(a): Auth) -> ApiResult<Json<HydrationState>> {
    let st = load(&state, a.user_id).await?;
    db::undo_drink(&state.db, a.user_id, day_start(&st.settings, Utc::now())).await?;
    Ok(Json(changed(&state, a.user_id).await?))
}

// ------------------------------------------------------------ horloge

/// Envoie les rappels dus. Chaque rappel est d'abord « réservé » en base
/// (mise à jour conditionnelle) : il n'est jamais envoyé deux fois.
pub async fn tick(state: &AppState, now: DateTime<Utc>) -> anyhow::Result<usize> {
    let mut sent = 0;
    for row in db::hydration_enabled(&state.db).await? {
        let settings = parse_settings(&row.settings);
        let due =
            next_reminder(&settings, row.last_reminder.max(row.last_drink), now).is_some_and(|t| t <= now);
        if !due || !db::claim_reminder(&state.db, row.user_id, row.last_reminder, now).await? {
            continue;
        }
        let (_, today_ml) = db::drinks_since(&state.db, row.user_id, day_start(&settings, now)).await?;
        // `today` et `goal` en verres : connecteurs d'avant les millilitres.
        let today_glasses = today_ml / settings.glass_ml.max(1);
        let (goal, goal_ml) = (settings.goal_glasses(), settings.goal_ml);
        state.hub.publish(
            row.user_id,
            ClientEvent::HydrationReminder {
                today: today_glasses,
                goal,
                today_ml,
                goal_ml,
            },
        );
        state.hub.broadcast_agents(
            row.user_id,
            &ServerMessage::HydrationReminder {
                today: today_glasses,
                goal,
                today_ml,
                goal_ml,
            },
            None,
        );
        if let Err(e) = changed(state, row.user_id).await {
            tracing::warn!("hydratation : {e:?}");
        }
        sent += 1;
    }
    Ok(sent)
}

pub fn spawn(state: AppState) {
    tokio::spawn(async move {
        let mut every = tokio::time::interval(TICK);
        loop {
            every.tick().await;
            if let Err(e) = tick(&state, Utc::now()).await {
                tracing::warn!("rappels d'hydratation : {e:#}");
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(s: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc)
    }

    fn settings() -> HydrationSettings {
        HydrationSettings {
            enabled: true,
            timezone: "Europe/Paris".into(),
            ..Default::default()
        }
    }

    #[test]
    fn validation() {
        assert!(settings().validate().is_ok());
        let bad = |f: fn(&mut HydrationSettings)| {
            let mut s = settings();
            f(&mut s);
            s.validate().is_err()
        };
        assert!(bad(|s| s.interval_minutes = 5));
        assert!(bad(|s| s.goal_ml = 100));
        assert!(bad(|s| s.glass_ml = 5000));
        assert!(bad(|s| s.start = "9h".into()));
        assert!(bad(|s| s.end = s.start.clone()));
        assert!(bad(|s| s.timezone = "Mars/Olympus".into()));
    }

    #[test]
    fn legacy_goal_in_glasses_is_converted() {
        let old = r#"{"enabled":true,"interval_minutes":30,"start":"09:00","end":"21:00","goal":6,"timezone":"UTC"}"#;
        let s = parse_settings(old);
        assert_eq!((s.goal_ml, s.glass_ml, s.goal), (1500, 250, None));
        assert!(s.validate().is_ok());
        // Réécrit sans l'ancien champ.
        assert!(!serde_json::to_string(&s).unwrap().contains("\"goal\""));
        // Objectif en ml déjà présent : gardé.
        let new = r#"{"enabled":true,"interval_minutes":30,"start":"09:00","end":"21:00","goal_ml":1800,"glass_ml":300,"timezone":"UTC"}"#;
        let s = parse_settings(new);
        assert_eq!((s.goal_ml, s.glass_ml, s.goal_glasses()), (1800, 300, 6));
    }

    #[test]
    fn reminders_follow_interval_and_window() {
        let s = settings(); // 09:00–21:00 à Paris (UTC+1 en novembre)
        // Avant l'ouverture : premier rappel à 09:45 heure locale.
        let now = at("2026-11-02T06:00:00Z");
        assert_eq!(next_reminder(&s, None, now), Some(at("2026-11-02T08:45:00Z")));
        // Un verre à 10:00 locale décale le rappel suivant à 10:45.
        let drank = at("2026-11-02T09:00:00Z");
        assert_eq!(
            next_reminder(&s, Some(drank), drank),
            Some(at("2026-11-02T09:45:00Z"))
        );
        // Trop tard dans la soirée : rappel le lendemain matin.
        let late = at("2026-11-02T19:30:00Z"); // 20:30 locale
        assert_eq!(
            next_reminder(&s, Some(late), late),
            Some(at("2026-11-03T08:45:00Z"))
        );
        // Rappel manqué dans la plage : dû tout de suite (dans le passé).
        let now = at("2026-11-02T12:00:00Z");
        assert!(next_reminder(&s, Some(at("2026-11-02T10:00:00Z")), now).unwrap() <= now);
        // Désactivé : aucun rappel.
        let off = HydrationSettings {
            enabled: false,
            ..settings()
        };
        assert_eq!(next_reminder(&off, None, now), None);
    }

    #[test]
    fn night_window_crosses_midnight() {
        let s = HydrationSettings {
            start: "22:00".into(),
            end: "02:00".into(),
            interval_minutes: 60,
            timezone: "UTC".into(),
            ..settings()
        };
        let now = at("2026-11-03T00:30:00Z");
        let last = at("2026-11-03T00:00:00Z");
        assert_eq!(
            next_reminder(&s, Some(last), now),
            Some(at("2026-11-03T01:00:00Z"))
        );
        // 01:30 + 60 min dépasse 02:00 : prochain à 23:00.
        let last = at("2026-11-03T01:30:00Z");
        assert_eq!(
            next_reminder(&s, Some(last), last),
            Some(at("2026-11-03T23:00:00Z"))
        );
    }

    #[test]
    fn day_start_is_local_midnight() {
        let s = settings();
        assert_eq!(
            day_start(&s, at("2026-11-02T23:30:00Z")),
            at("2026-11-02T23:00:00Z")
        );
        assert_eq!(
            day_start(&s, at("2026-11-02T22:30:00Z")),
            at("2026-11-01T23:00:00Z")
        );
    }
}
