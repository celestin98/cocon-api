//! Protocole de l'API, côté serveur.
//!
//! Le format est identique à celui de Cocon (`cocon_core::remote`), mais le
//! serveur reste indépendant de l'application de bureau : la configuration
//! et l'état des sessions sont des objets JSON opaques, de taille bornée.
//! C'est le connecteur du PC qui revalide entièrement une configuration
//! avant de l'appliquer.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Taille maximale d'un corps de requête ou d'un message WebSocket.
pub const MAX_BODY_BYTES: usize = 256 * 1024;
/// Taille maximale d'une configuration stockée.
pub const MAX_CONFIG_BYTES: usize = 64 * 1024;
pub const MAX_TASKS: usize = 500;
pub const MAX_TASK_TEXT: usize = 1000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceKind {
    Desktop,
    Mobile,
    /// Navigateur (interface web, session par cookie).
    Web,
}

// ------------------------------------------------------------ authentification

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
    #[serde(default)]
    pub totp: Option<String>,
    pub device_name: String,
    pub device_kind: DeviceKind,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenPair {
    pub access_token: String,
    pub expires_in: u64,
    pub refresh_token: String,
    pub device_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RefreshRequest {
    pub refresh_token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiError {
    pub error: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Me {
    pub email: String,
    pub totp_enabled: bool,
    pub device_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub id: String,
    pub name: String,
    pub kind: DeviceKind,
    pub created: DateTime<Utc>,
    pub last_seen: Option<DateTime<Utc>>,
    pub online: bool,
    pub current: bool,
}

// ------------------------------------------------------------ interface web

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignupMode {
    /// Inscription libre.
    Open,
    /// Sur invitation (`cocon-api invite`).
    Invite,
    /// Fermée : comptes créés en ligne de commande uniquement.
    Closed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebInfo {
    pub signup: SignupMode,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignupRequest {
    pub email: String,
    pub password: String,
    #[serde(default)]
    pub invite: Option<String>,
}

/// Inscription libre : compte créé, adresse à confirmer par le code reçu.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignupPending {
    pub email: String,
    pub verify: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifyEmailRequest {
    pub email: String,
    pub code: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResendCodeRequest {
    pub email: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebLogin {
    pub email: String,
    pub password: String,
    #[serde(default)]
    pub totp: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PasswordChange {
    pub current: String,
    pub new: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PasswordOnly {
    pub password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TotpCode {
    pub code: String,
    #[serde(default)]
    pub password: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TotpSetup {
    /// Clé à saisir à la main.
    pub secret: String,
    /// `otpauth://…`
    pub url: String,
    /// QR code PNG en base64.
    pub qr_png: String,
}

/// Adresse e-mail plausible (pas de vérification d'existence).
pub fn clean_email(email: &str) -> Result<String, String> {
    let e = email.trim().to_lowercase();
    let ok = e.len() <= 254
        && e.split_once('@').is_some_and(|(local, domain)| {
            !local.is_empty() && domain.contains('.') && !domain.starts_with('.') && !domain.ends_with('.')
        })
        && !e.chars().any(|c| c.is_whitespace() || c.is_control());
    if ok {
        Ok(e)
    } else {
        Err("adresse e-mail invalide".into())
    }
}

// ------------------------------------------------------------ données

/// Tâche (même format que `~/.config/cocon/tasks.toml`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Task {
    pub id: String,
    pub text: String,
    #[serde(default)]
    pub done: bool,
    #[serde(default)]
    pub for_session: bool,
    pub created: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub done_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionedConfig {
    pub version: u64,
    pub config: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionedTasks {
    pub version: u64,
    pub tasks: Vec<Task>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NewTask {
    pub text: String,
    #[serde(default)]
    pub for_session: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskPatch {
    #[serde(default)]
    pub text: Option<String>,
    #[serde(default)]
    pub done: Option<bool>,
    #[serde(default)]
    pub for_session: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionView {
    pub device_id: String,
    pub device_name: String,
    pub online: bool,
    pub status: Option<Value>,
    pub updated: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StartRequest {
    #[serde(default)]
    pub minutes: Option<u32>,
    #[serde(default)]
    pub device_id: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StopRequest {
    #[serde(default)]
    pub confirmation: String,
    #[serde(default)]
    pub device_id: Option<String>,
}

// ------------------------------------------------------------ connecteur (PC)

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AgentAction {
    Start { minutes: Option<u32> },
    Stop { confirmation: String },
    ApplyConfig { version: u64, config: Value },
    ApplyTasks { version: u64, tasks: Vec<Task> },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentCommand {
    pub id: String,
    pub expires_at: DateTime<Utc>,
    pub action: AgentAction,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum CommandOutcome {
    Done,
    /// `reply` : `{"result":"stopped"}`, `{"result":"need_phrase","detail":…}`
    /// ou `{"result":"need_hold","detail":3}`.
    Stop {
        reply: Value,
    },
    Failed {
        message: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AgentMessage {
    Hello {
        config_version: u64,
        tasks_version: u64,
        #[serde(default)]
        config: Option<Value>,
        #[serde(default)]
        tasks: Option<Vec<Task>>,
    },
    Status {
        status: Option<Value>,
    },
    Result {
        id: String,
        outcome: CommandOutcome,
    },
    ConfigChanged {
        base_version: u64,
        config: Value,
    },
    TasksChanged {
        base_version: u64,
        tasks: Vec<Task>,
    },
    /// « J'ai bu » depuis la notification du PC (connecteurs d'avant la
    /// synchronisation : un verre).
    HydrationDrink,
    /// Prises notées ou annulées sur le PC, à reporter.
    HydrationSync {
        #[serde(default)]
        entries: Vec<Drink>,
        #[serde(default)]
        removed: Vec<String>,
    },
    /// Réglages d'hydratation modifiés sur le PC.
    HydrationSettings(AgentHydrationSettings),
}

/// Une prise d'eau, identifiée par l'appareil qui l'a notée.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Drink {
    pub id: String,
    pub at: DateTime<Utc>,
    pub ml: u32,
}

/// Réglages que le PC sait modifier (la plage horaire se règle sur le web).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentHydrationSettings {
    pub enabled: bool,
    pub interval_minutes: u32,
    pub goal_ml: u32,
    pub glass_ml: u32,
    /// Fuseau du PC, retenu seulement si le compte n'a encore rien réglé.
    #[serde(default)]
    pub timezone: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerMessage {
    Command(AgentCommand),
    ConfigAccepted {
        version: u64,
    },
    TasksAccepted {
        version: u64,
    },
    /// Rappel d'hydratation à afficher (`today`, `goal` : en verres).
    HydrationReminder {
        today: u32,
        goal: u32,
        today_ml: u32,
        goal_ml: u32,
    },
    /// Verre enregistré (ici ou ailleurs) : retirer le rappel affiché.
    HydrationAcknowledged,
    /// Réglages et prises des derniers jours (depuis `since`) : le PC
    /// aligne son journal local.
    HydrationSync {
        since: DateTime<Utc>,
        entries: Vec<Drink>,
        settings: crate::hydration::HydrationSettings,
        configured: bool,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientEvent {
    Session(SessionView),
    ConfigChanged {
        version: u64,
    },
    TasksChanged {
        version: u64,
    },
    DevicesChanged,
    /// C'est l'heure de boire un verre d'eau.
    HydrationReminder {
        today: u32,
        goal: u32,
        today_ml: u32,
        goal_ml: u32,
    },
    /// Réglages ou compteur d'hydratation modifiés.
    HydrationChanged(Box<crate::hydration::HydrationState>),
    /// Battement régulier : le client sait que le canal est vivant.
    Heartbeat,
}

// ------------------------------------------------------------ validation

/// Configuration : un objet JSON de taille raisonnable.
pub fn validate_config(v: &Value) -> Result<String, String> {
    if !v.is_object() {
        return Err("la configuration doit être un objet JSON".into());
    }
    let text = serde_json::to_string(v).map_err(|e| e.to_string())?;
    if text.len() > MAX_CONFIG_BYTES {
        return Err(format!(
            "configuration trop volumineuse (> {MAX_CONFIG_BYTES} octets)"
        ));
    }
    Ok(text)
}

/// Texte d'une tâche nettoyé (espaces regroupés), ou erreur.
pub fn clean_task_text(text: &str) -> Result<String, String> {
    let t = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if t.is_empty() {
        return Err("le texte de la tâche est vide".into());
    }
    if t.chars().count() > MAX_TASK_TEXT || t.chars().any(char::is_control) {
        return Err("texte de tâche invalide".into());
    }
    Ok(t)
}

fn valid_id(id: &str) -> bool {
    (1..=64).contains(&id.len())
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

/// Liste complète reçue d'un client : bornée, identifiants uniques.
pub fn validate_tasks(tasks: &mut [Task]) -> Result<(), String> {
    if tasks.len() > MAX_TASKS {
        return Err(format!("au plus {MAX_TASKS} tâches"));
    }
    let mut seen = std::collections::HashSet::new();
    for t in tasks.iter_mut() {
        if !valid_id(&t.id) || !seen.insert(t.id.clone()) {
            return Err(format!("identifiant de tâche invalide ou en double : {}", t.id));
        }
        t.text = clean_task_text(&t.text)?;
        if t.done {
            t.for_session = false;
        }
    }
    Ok(())
}

/// Nom d'appareil affiché : 1 à 64 caractères imprimables.
pub fn clean_device_name(name: &str) -> Result<String, String> {
    let n = name.trim();
    if n.is_empty() || n.chars().count() > 64 || n.chars().any(char::is_control) {
        return Err("nom d'appareil invalide (1 à 64 caractères)".into());
    }
    Ok(n.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_format_matches_cocon() {
        // Même JSON que cocon_core::remote (voir ses tests).
        let cmd = AgentCommand {
            id: "c1".into(),
            expires_at: DateTime::<Utc>::UNIX_EPOCH,
            action: AgentAction::Stop {
                confirmation: "maintenu".into(),
            },
        };
        let json = serde_json::to_string(&ServerMessage::Command(cmd)).unwrap();
        assert!(json.contains(r#""type":"command""#), "{json}");
        assert!(
            json.contains(r#""action":{"type":"stop","confirmation":"maintenu"}"#),
            "{json}"
        );
        let m: AgentMessage = serde_json::from_str(
            r#"{"type":"result","id":"c1","outcome":{"outcome":"stop","reply":{"result":"need_hold","detail":3}}}"#,
        )
        .unwrap();
        assert!(matches!(m, AgentMessage::Result { .. }));
    }

    #[test]
    fn validation() {
        assert!(validate_config(&serde_json::json!([1])).is_err());
        assert!(validate_config(&serde_json::json!({"a": "x".repeat(MAX_CONFIG_BYTES)})).is_err());
        assert!(validate_config(&serde_json::json!({"session": {}})).is_ok());
        assert_eq!(clean_task_text("  a   b ").unwrap(), "a b");
        assert!(clean_task_text("   ").is_err());
        let t = |id: &str| Task {
            id: id.into(),
            text: "x".into(),
            done: true,
            for_session: true,
            created: Utc::now(),
            done_at: None,
        };
        let mut ok = vec![t("a-1"), t("b_2")];
        validate_tasks(&mut ok).unwrap();
        assert!(!ok[0].for_session, "une tâche terminée n'est plus proposée");
        assert!(validate_tasks(&mut [t("a"), t("a")]).is_err());
        assert!(validate_tasks(&mut [t("../x")]).is_err());
        assert!(clean_device_name("PC\u{7}").is_err());
        assert_eq!(clean_email("  Moi@Exemple.ORG ").unwrap(), "moi@exemple.org");
        for bad in ["moi", "@x.fr", "moi@x", "moi@.fr", "m oi@x.fr", "moi@x.fr."] {
            assert!(clean_email(bad).is_err(), "{bad}");
        }
    }
}
