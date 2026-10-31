//! Rappels d'hydratation.
//!
//! C'est le serveur qui décide quand rappeler de boire un verre d'eau, puis
//! qui prévient tous les appareils du compte : connecteur du PC
//! (notification), interface web, application mobile. Réglages, compteur du
//! jour et horloge des rappels vivent ici et non sur les appareils : le
//! rythme est le même partout, que le PC soit allumé ou non.
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
use crate::protocol::{ClientEvent, ServerMessage};
use crate::routes::{ApiResult, AppState, Auth, Error};

pub const MIN_INTERVAL: u32 = 15;
pub const MAX_INTERVAL: u32 = 240;
pub const MAX_GOAL: u32 = 30;
/// Verres enregistrables par jour (garde-fou contre les clics en rafale).
pub const MAX_DRINKS_PER_DAY: u32 = 60;
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
    /// Verres visés par jour.
    pub goal: u32,
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
            goal: 8,
            timezone: "UTC".into(),
        }
    }
}

fn parse_time(s: &str) -> Option<NaiveTime> {
    NaiveTime::parse_from_str(s, "%H:%M").ok()
}

impl HydrationSettings {
    pub fn validate(&self) -> Result<(), String> {
        if !(MIN_INTERVAL..=MAX_INTERVAL).contains(&self.interval_minutes) {
            return Err(format!(
                "intervalle entre {MIN_INTERVAL} et {MAX_INTERVAL} minutes"
            ));
        }
        if !(1..=MAX_GOAL).contains(&self.goal) {
            return Err(format!("objectif entre 1 et {MAX_GOAL} verres"));
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
    /// Verres bus depuis minuit (heure locale).
    pub today: u32,
    pub last_drink: Option<DateTime<Utc>>,
    /// Prochain rappel prévu (`None` : rappels désactivés).
    pub next_reminder: Option<DateTime<Utc>>,
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

async fn load(
    state: &AppState,
    user: i64,
) -> ApiResult<(HydrationSettings, Option<DateTime<Utc>>, Option<DateTime<Utc>>)> {
    Ok(match db::hydration(&state.db, user).await? {
        Some(row) => (
            serde_json::from_str(&row.settings).unwrap_or_default(),
            row.last_reminder,
            row.last_drink,
        ),
        None => (HydrationSettings::default(), None, None),
    })
}

pub async fn read(state: &AppState, user: i64) -> ApiResult<HydrationState> {
    let (settings, last_reminder, last_drink) = load(state, user).await?;
    let now = Utc::now();
    let today = db::drinks_since(&state.db, user, day_start(&settings, now)).await?;
    let next = next_reminder(&settings, last_reminder.max(last_drink), now).map(|t| t.max(now));
    Ok(HydrationState {
        settings,
        today,
        last_drink,
        next_reminder: next,
    })
}

/// État publié à tous les clients après un changement.
async fn changed(state: &AppState, user: i64) -> ApiResult<HydrationState> {
    let s = read(state, user).await?;
    state
        .hub
        .publish(user, ClientEvent::HydrationChanged(Box::new(s.clone())));
    Ok(s)
}

/// Un verre de plus (depuis n'importe quel appareil). Les rappels encore
/// affichés ailleurs sont retirés.
pub async fn drink(state: &AppState, user: i64, device: &str) -> ApiResult<HydrationState> {
    let (settings, _, _) = load(state, user).await?;
    let since = day_start(&settings, Utc::now());
    let defaults = serde_json::to_string(&settings).map_err(anyhow::Error::from)?;
    if !db::add_drink(&state.db, user, device, since, MAX_DRINKS_PER_DAY, &defaults).await? {
        return Err(Error::new(
            StatusCode::TOO_MANY_REQUESTS,
            "limit",
            format!("Au plus {MAX_DRINKS_PER_DAY} verres par jour"),
        ));
    }
    state
        .hub
        .broadcast_agents(user, &ServerMessage::HydrationAcknowledged, None);
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
    settings.validate().map_err(Error::bad_request)?;
    let body = serde_json::to_string(&settings).map_err(anyhow::Error::from)?;
    // Nouveau rythme : l'horloge repart de maintenant.
    db::put_hydration(&state.db, a.user_id, &body, settings.enabled).await?;
    Ok(Json(changed(&state, a.user_id).await?))
}

pub async fn post_drink(State(state): State<AppState>, Auth(a): Auth) -> ApiResult<Json<HydrationState>> {
    Ok(Json(drink(&state, a.user_id, &a.device_id).await?))
}

/// Annule le dernier verre du jour (clic par erreur).
pub async fn delete_drink(State(state): State<AppState>, Auth(a): Auth) -> ApiResult<Json<HydrationState>> {
    let (settings, _, _) = load(&state, a.user_id).await?;
    db::undo_drink(&state.db, a.user_id, day_start(&settings, Utc::now())).await?;
    Ok(Json(changed(&state, a.user_id).await?))
}

// ------------------------------------------------------------ horloge

/// Envoie les rappels dus. Chaque rappel est d'abord « réservé » en base
/// (mise à jour conditionnelle) : il n'est jamais envoyé deux fois.
pub async fn tick(state: &AppState, now: DateTime<Utc>) -> anyhow::Result<usize> {
    let mut sent = 0;
    for row in db::hydration_enabled(&state.db).await? {
        let Ok(settings) = serde_json::from_str::<HydrationSettings>(&row.settings) else {
            continue;
        };
        let due =
            next_reminder(&settings, row.last_reminder.max(row.last_drink), now).is_some_and(|t| t <= now);
        if !due || !db::claim_reminder(&state.db, row.user_id, row.last_reminder, now).await? {
            continue;
        }
        let today = db::drinks_since(&state.db, row.user_id, day_start(&settings, now)).await?;
        let goal = settings.goal;
        state
            .hub
            .publish(row.user_id, ClientEvent::HydrationReminder { today, goal });
        state.hub.broadcast_agents(
            row.user_id,
            &ServerMessage::HydrationReminder { today, goal },
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
        assert!(bad(|s| s.goal = 0));
        assert!(bad(|s| s.start = "9h".into()));
        assert!(bad(|s| s.end = s.start.clone()));
        assert!(bad(|s| s.timezone = "Mars/Olympus".into()));
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
