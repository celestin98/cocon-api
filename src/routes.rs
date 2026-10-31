//! Routes HTTP de l'API (`/v1`).

use std::convert::Infallible;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{ConnectInfo, FromRequestParts, Path, State};
use axum::http::request::Parts;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use chrono::Utc;
use serde_json::Value;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::set_header::SetResponseHeaderLayer;
use tower_http::timeout::TimeoutLayer;

use crate::auth::{self, Authenticated, RateLimiter, RefreshOutcome};
use crate::db::{self, Db, DeviceRow};
use crate::hub::{CommandError, Hub};
use crate::protocol::*;
use crate::ws;

pub const DOC_CONFIG: &str = "config";
pub const DOC_TASKS: &str = "tasks";

#[derive(Clone)]
pub struct AppState {
    pub db: Db,
    pub hub: Arc<Hub>,
    /// Connexions : 10 tentatives par IP et par 10 minutes.
    pub login_limiter: Arc<RateLimiter>,
    /// Renouvellements : plus large (reconnexions des connecteurs).
    pub refresh_limiter: Arc<RateLimiter>,
    /// Inscriptions : 5 par IP et par heure.
    pub signup_limiter: Arc<RateLimiter>,
    pub signup: SignupMode,
    /// Proxy sur un réseau privé : voir [`ClientIp`].
    pub behind_proxy: bool,
}

impl AppState {
    pub fn new(db: Db) -> Self {
        Self {
            db,
            hub: Arc::default(),
            login_limiter: Arc::new(RateLimiter::new(10, Duration::from_secs(600))),
            refresh_limiter: Arc::new(RateLimiter::new(120, Duration::from_secs(600))),
            signup_limiter: Arc::new(RateLimiter::new(5, Duration::from_secs(3600))),
            signup: SignupMode::Open,
            behind_proxy: false,
        }
    }
}

// ------------------------------------------------------------ erreurs

#[derive(Debug)]
pub struct Error {
    status: StatusCode,
    code: &'static str,
    message: String,
}

impl Error {
    pub fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
        }
    }

    pub fn unauthorized() -> Self {
        Self::new(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "Authentification requise",
        )
    }

    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "invalid_request", message)
    }

    pub fn too_many() -> Self {
        Self::new(
            StatusCode::TOO_MANY_REQUESTS,
            "too_many_attempts",
            "Trop de tentatives : réessayez dans quelques minutes",
        )
    }
}

impl From<anyhow::Error> for Error {
    fn from(e: anyhow::Error) -> Self {
        // Le détail reste dans les journaux du serveur, jamais dans la réponse.
        tracing::error!("erreur interne : {e:#}");
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "internal", "Erreur interne")
    }
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(ApiError {
                error: self.code.to_owned(),
                message: self.message,
            }),
        )
            .into_response()
    }
}

pub type ApiResult<T> = Result<T, Error>;

// ------------------------------------------------------------ extracteurs

/// Adresse du client. Derrière un reverse proxy (pair sur la boucle locale,
/// ou sur un réseau privé avec `--behind-proxy`), on prend la dernière entrée
/// de `X-Forwarded-For`, celle ajoutée par le proxy ; un client distant ne
/// peut pas la falsifier.
pub struct ClientIp(pub IpAddr);

fn is_private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_private(),
        IpAddr::V6(v6) => v6.is_unique_local(),
    }
}

impl FromRequestParts<AppState> for ClientIp {
    type Rejection = Infallible;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Infallible> {
        let peer = parts
            .extensions
            .get::<ConnectInfo<SocketAddr>>()
            .map_or(IpAddr::V4(Ipv4Addr::LOCALHOST), |c| c.0.ip());
        if (peer.is_loopback() || (state.behind_proxy && is_private(peer)))
            && let Some(ip) = parts
                .headers
                .get("x-forwarded-for")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.rsplit(',').next())
                .and_then(|s| s.trim().parse().ok())
        {
            return Ok(ClientIp(ip));
        }
        Ok(ClientIp(peer))
    }
}

/// Appareil authentifié : `Authorization: Bearer <jeton d'accès>` (API,
/// mobile, PC) ou cookie de session `__Host-cocon` (interface web).
///
/// Avec le cookie, toute requête qui modifie quelque chose — et l'ouverture
/// d'un WebSocket — doit venir de la même origine ; les modifications
/// exigent en plus l'en-tête `X-Cocon-Csrf: 1`, qu'un site tiers ne peut
/// pas ajouter sans pré-vérification CORS (refusée).
pub struct Auth(pub Authenticated);

pub const SESSION_COOKIE: &str = "__Host-cocon";

pub fn cookie_value(headers: &axum::http::HeaderMap, name: &str) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|kv| kv.trim().split_once('='))
        .find(|(k, _)| *k == name)
        .map(|(_, v)| v.to_owned())
}

/// L'en-tête `Origin` désigne-t-il ce même serveur (même hôte que `Host`) ?
pub fn same_origin(headers: &axum::http::HeaderMap) -> bool {
    let host = headers.get(header::HOST).and_then(|v| v.to_str().ok());
    let origin = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok());
    match (host, origin) {
        (Some(host), Some(origin)) => origin
            .strip_prefix("https://")
            .or_else(|| origin.strip_prefix("http://"))
            .is_some_and(|o| o.eq_ignore_ascii_case(host)),
        _ => false,
    }
}

impl FromRequestParts<AppState> for Auth {
    type Rejection = Error;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Error> {
        let bearer = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .map(str::trim)
            .filter(|t| !t.is_empty() && t.len() < 200)
            .map(str::to_owned);
        let found = if let Some(token) = bearer {
            auth::check_access(&state.db, &token).await?
        } else if let Some(token) = cookie_value(&parts.headers, SESSION_COOKIE).filter(|t| t.len() < 200) {
            let safe = matches!(parts.method, axum::http::Method::GET | axum::http::Method::HEAD);
            let websocket = parts
                .headers
                .get(header::UPGRADE)
                .is_some_and(|v| v.as_bytes().eq_ignore_ascii_case(b"websocket"));
            let csrf_ok = parts.headers.get("x-cocon-csrf").is_some_and(|v| v == "1");
            if (!safe || websocket) && !same_origin(&parts.headers) || !safe && !csrf_ok {
                return Err(Error::new(
                    StatusCode::FORBIDDEN,
                    "csrf",
                    "Requête refusée : origine non autorisée",
                ));
            }
            auth::check_web(&state.db, &token).await?
        } else {
            None
        };
        if let Some(a) = &found {
            db::touch_device(&state.db, &a.device_id).await?;
        }
        found.map(Auth).ok_or_else(Error::unauthorized)
    }
}

// ------------------------------------------------------------ routeur

pub fn router(state: AppState) -> Router {
    let api = Router::new()
        .route("/auth/login", post(login))
        .route("/auth/refresh", post(refresh))
        .route("/auth/logout", post(logout))
        .route("/me", get(me))
        .route("/devices", get(devices))
        .route("/devices/{id}", delete(revoke_device))
        .route("/config", get(get_config).put(put_config))
        .route("/tasks", get(get_tasks).put(put_tasks).post(add_task))
        .route(
            "/tasks/{id}",
            axum::routing::patch(patch_task).delete(delete_task),
        )
        .route("/session", get(session))
        .route("/session/start", post(start))
        .route("/session/stop", post(stop))
        .route(
            "/hydration",
            get(crate::hydration::get).put(crate::hydration::put),
        )
        .route(
            "/hydration/drink",
            post(crate::hydration::post_drink).delete(crate::hydration::delete_drink),
        )
        .route("/events", get(ws::events))
        .route("/agent", get(ws::agent));

    let headers = [
        (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        (header::CACHE_CONTROL, "no-store"),
        (header::X_FRAME_OPTIONS, "DENY"),
        (header::REFERRER_POLICY, "no-referrer"),
        (
            header::CONTENT_SECURITY_POLICY,
            "default-src 'none'; script-src 'self'; style-src 'self'; font-src 'self'; img-src 'self' data:; \
             connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
        ),
        (header::STRICT_TRANSPORT_SECURITY, "max-age=31536000"),
    ];
    let mut app = Router::new()
        .route("/health", get(|| async { "ok" }))
        .nest("/v1", api)
        .merge(crate::web::router())
        .with_state(state)
        .layer(RequestBodyLimitLayer::new(MAX_BODY_BYTES))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            Duration::from_secs(30),
        ));
    for (name, value) in headers {
        app = app.layer(SetResponseHeaderLayer::overriding(
            name,
            HeaderValue::from_static(value),
        ));
    }
    app
}

// ------------------------------------------------------------ authentification

pub fn audit(
    state: &AppState,
    user: Option<i64>,
    device: Option<String>,
    ip: IpAddr,
    event: &'static str,
    detail: String,
) {
    let db = state.db.clone();
    tokio::spawn(async move {
        db::audit(
            &db,
            user,
            device.as_deref(),
            Some(&ip.to_string()),
            event,
            &detail,
        )
        .await;
    });
}

/// Vérifie identifiants et code TOTP : limitation par IP, durée constante,
/// verrouillage après échecs, code à usage unique. Commun à l'API et au web.
pub async fn check_credentials(
    state: &AppState,
    ip: IpAddr,
    email_in: &str,
    password_in: &str,
    totp: Option<&str>,
) -> ApiResult<db::UserRow> {
    if !state.login_limiter.allow(ip) {
        audit(state, None, None, ip, "login_rate_limited", String::new());
        return Err(Error::too_many());
    }
    let invalid = || {
        Error::new(
            StatusCode::UNAUTHORIZED,
            "invalid_credentials",
            "Identifiants invalides",
        )
    };
    let email = email_in.trim().to_lowercase();
    if email.len() > 254 || password_in.len() > 1024 {
        return Err(invalid());
    }

    let user = db::user_by_email(&state.db, &email).await?;
    // Vérification toujours faite (même pour un compte inconnu) : même durée.
    let (hash, password) = (
        user.as_ref()
            .map_or_else(|| auth::dummy_hash().to_owned(), |u| u.pw_hash.clone()),
        password_in.to_owned(),
    );
    let password_ok = tokio::task::spawn_blocking(move || auth::verify_password(&password, &hash))
        .await
        .map_err(|e| anyhow::anyhow!(e))?;

    let Some(user) = user else {
        audit(
            state,
            None,
            None,
            ip,
            "login_failed",
            format!("compte inconnu {email}"),
        );
        return Err(invalid());
    };
    if user.locked_until.is_some_and(|t| t > Utc::now()) {
        audit(state, Some(user.id), None, ip, "login_locked", String::new());
        return Err(Error::too_many());
    }
    if !password_ok {
        db::record_failure(&state.db, user.id, auth::MAX_FAILURES, auth::LOCK_FOR).await?;
        audit(
            state,
            Some(user.id),
            None,
            ip,
            "login_failed",
            "mot de passe".into(),
        );
        return Err(invalid());
    }
    if let Some(secret) = &user.totp_secret {
        let Some(code) = totp.filter(|c| !c.trim().is_empty()) else {
            return Err(Error::new(
                StatusCode::UNAUTHORIZED,
                "totp_required",
                "Code de double authentification requis",
            ));
        };
        // Le pas n'est accepté qu'une fois, même si le même code arrive en
        // parallèle (mise à jour conditionnelle en base).
        let step = auth::check_totp(secret, &user.email, code, user.totp_last_step);
        let accepted = match step {
            Some(s) => db::use_totp_step(&state.db, user.id, s).await?,
            None => false,
        };
        if !accepted {
            db::record_failure(&state.db, user.id, auth::MAX_FAILURES, auth::LOCK_FOR).await?;
            audit(state, Some(user.id), None, ip, "login_failed", "code TOTP".into());
            return Err(Error::new(
                StatusCode::UNAUTHORIZED,
                "invalid_totp",
                "Code de double authentification invalide",
            ));
        }
    }

    Ok(user)
}

async fn login(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Json(req): Json<LoginRequest>,
) -> ApiResult<Json<TokenPair>> {
    let name = clean_device_name(&req.device_name).map_err(Error::bad_request)?;
    let user = check_credentials(&state, ip, &req.email, &req.password, req.totp.as_deref()).await?;
    let device = auth::random_id();
    db::reset_failures(&state.db, user.id).await?;
    db::create_device(&state.db, &device, user.id, &name, req.device_kind).await?;
    let pair = auth::issue_tokens(&state.db, &device).await?;
    audit(
        &state,
        Some(user.id),
        Some(device),
        ip,
        "login_ok",
        format!("{:?} « {} »", req.device_kind, req.device_name.trim()),
    );
    state.hub.publish(user.id, ClientEvent::DevicesChanged);
    Ok(Json(pair))
}

async fn refresh(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Json(req): Json<RefreshRequest>,
) -> ApiResult<Json<TokenPair>> {
    if !state.refresh_limiter.allow(ip) {
        return Err(Error::too_many());
    }
    if req.refresh_token.len() > 200 {
        return Err(Error::unauthorized());
    }
    match auth::refresh(&state.db, &req.refresh_token).await? {
        RefreshOutcome::Ok(pair) => Ok(Json(pair)),
        RefreshOutcome::Invalid => Err(Error::unauthorized()),
        RefreshOutcome::Reused { device_id, user_id } => {
            // Jeton déjà utilisé : copie volée ou course. L'appareil est révoqué.
            state.hub.disconnect(user_id, &device_id);
            state.hub.publish(user_id, ClientEvent::DevicesChanged);
            audit(
                &state,
                Some(user_id),
                Some(device_id),
                ip,
                "refresh_reuse",
                "appareil révoqué".into(),
            );
            Err(Error::unauthorized())
        }
    }
}

async fn logout(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Auth(a): Auth,
) -> ApiResult<StatusCode> {
    db::revoke_device(&state.db, &a.device_id).await?;
    state.hub.disconnect(a.user_id, &a.device_id);
    state.hub.publish(a.user_id, ClientEvent::DevicesChanged);
    audit(
        &state,
        Some(a.user_id),
        Some(a.device_id),
        ip,
        "logout",
        String::new(),
    );
    Ok(StatusCode::NO_CONTENT)
}

async fn me(State(state): State<AppState>, Auth(a): Auth) -> ApiResult<Json<Me>> {
    let user = db::user_by_id(&state.db, a.user_id)
        .await?
        .ok_or_else(Error::unauthorized)?;
    Ok(Json(Me {
        email: user.email,
        totp_enabled: user.totp_secret.is_some(),
        device_id: a.device_id,
    }))
}

// ------------------------------------------------------------ appareils

async fn devices(State(state): State<AppState>, Auth(a): Auth) -> ApiResult<Json<Vec<DeviceInfo>>> {
    let uid = a.user_id;
    let rows = db::list_devices(&state.db, uid).await?;
    Ok(Json(
        rows.into_iter()
            .map(|d| DeviceInfo {
                online: state.hub.is_online(uid, &d.id),
                current: d.id == a.device_id,
                id: d.id,
                name: d.name,
                kind: d.kind,
                created: d.created,
                last_seen: d.last_seen,
            })
            .collect(),
    ))
}

async fn revoke_device(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Auth(a): Auth,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    // Un appareil d'un autre compte est « introuvable », comme un absent.
    let done = match db::device(&state.db, &id).await? {
        Some(d) if d.user_id == a.user_id && !d.revoked => db::revoke_device(&state.db, &id).await?,
        _ => false,
    };
    if !done {
        return Err(Error::new(
            StatusCode::NOT_FOUND,
            "not_found",
            "Appareil introuvable",
        ));
    }
    state.hub.disconnect(a.user_id, &id);
    state.hub.publish(a.user_id, ClientEvent::DevicesChanged);
    audit(
        &state,
        Some(a.user_id),
        Some(a.device_id),
        ip,
        "device_revoked",
        id,
    );
    Ok(StatusCode::NO_CONTENT)
}

// ------------------------------------------------------------ configuration

pub async fn read_config(state: &AppState, user: i64) -> ApiResult<VersionedConfig> {
    let doc = db::document(&state.db, user, DOC_CONFIG).await?;
    Ok(match doc {
        Some((version, body)) => VersionedConfig {
            version,
            config: serde_json::from_str(&body).map_err(anyhow::Error::from)?,
        },
        None => VersionedConfig {
            version: 0,
            config: Value::Null,
        },
    })
}

/// Enregistre une configuration fondée sur `base` ; prévient clients et PC
/// (sauf `from`, l'appareil d'origine). `None` : conflit de version.
pub async fn store_config(
    state: &AppState,
    user: i64,
    base: u64,
    config: Value,
    from: Option<&str>,
) -> ApiResult<Option<u64>> {
    let body = validate_config(&config).map_err(Error::bad_request)?;
    let version = db::put_document(&state.db, user, DOC_CONFIG, base, &body).await?;
    if let Some(v) = version {
        state.hub.publish(user, ClientEvent::ConfigChanged { version: v });
        let cmd = crate::hub::Hub::new_command(AgentAction::ApplyConfig { version: v, config });
        state
            .hub
            .broadcast_agents(user, &ServerMessage::Command(cmd), from);
    }
    Ok(version)
}

fn conflict(current: u64) -> Error {
    Error::new(
        StatusCode::CONFLICT,
        "conflict",
        format!("Version périmée : la version actuelle est {current}. Relisez avant de modifier."),
    )
}

async fn get_config(State(state): State<AppState>, Auth(a): Auth) -> ApiResult<Json<VersionedConfig>> {
    Ok(Json(read_config(&state, a.user_id).await?))
}

async fn put_config(
    State(state): State<AppState>,
    Auth(a): Auth,
    Json(req): Json<VersionedConfig>,
) -> ApiResult<Json<VersionedConfig>> {
    match store_config(&state, a.user_id, req.version, req.config.clone(), None).await? {
        Some(version) => Ok(Json(VersionedConfig {
            version,
            config: req.config,
        })),
        None => Err(conflict(read_config(&state, a.user_id).await?.version)),
    }
}

// ------------------------------------------------------------ tâches

pub async fn read_tasks(state: &AppState, user: i64) -> ApiResult<VersionedTasks> {
    let doc = db::document(&state.db, user, DOC_TASKS).await?;
    Ok(match doc {
        Some((version, body)) => VersionedTasks {
            version,
            tasks: serde_json::from_str(&body).map_err(anyhow::Error::from)?,
        },
        None => VersionedTasks {
            version: 0,
            tasks: Vec::new(),
        },
    })
}

pub async fn store_tasks(
    state: &AppState,
    user: i64,
    base: u64,
    mut tasks: Vec<Task>,
    from: Option<&str>,
) -> ApiResult<Option<u64>> {
    validate_tasks(&mut tasks).map_err(Error::bad_request)?;
    let body = serde_json::to_string(&tasks).map_err(anyhow::Error::from)?;
    let version = db::put_document(&state.db, user, DOC_TASKS, base, &body).await?;
    if let Some(v) = version {
        state.hub.publish(user, ClientEvent::TasksChanged { version: v });
        let cmd = crate::hub::Hub::new_command(AgentAction::ApplyTasks { version: v, tasks });
        state
            .hub
            .broadcast_agents(user, &ServerMessage::Command(cmd), from);
    }
    Ok(version)
}

async fn get_tasks(State(state): State<AppState>, Auth(a): Auth) -> ApiResult<Json<VersionedTasks>> {
    Ok(Json(read_tasks(&state, a.user_id).await?))
}

async fn put_tasks(
    State(state): State<AppState>,
    Auth(a): Auth,
    Json(req): Json<VersionedTasks>,
) -> ApiResult<Json<VersionedTasks>> {
    match store_tasks(&state, a.user_id, req.version, req.tasks, None).await? {
        Some(_) => Ok(Json(read_tasks(&state, a.user_id).await?)),
        None => Err(conflict(read_tasks(&state, a.user_id).await?.version)),
    }
}

/// Modification d'une tâche : relit, applique, réessaie en cas de course.
async fn edit_tasks(
    state: &AppState,
    user: i64,
    op: impl Fn(&mut Vec<Task>) -> ApiResult<()>,
) -> ApiResult<VersionedTasks> {
    for _ in 0..5 {
        let mut current = read_tasks(state, user).await?;
        op(&mut current.tasks)?;
        if store_tasks(state, user, current.version, current.tasks, None)
            .await?
            .is_some()
        {
            return read_tasks(state, user).await;
        }
    }
    Err(conflict(read_tasks(state, user).await?.version))
}

async fn add_task(
    State(state): State<AppState>,
    Auth(a): Auth,
    Json(req): Json<NewTask>,
) -> ApiResult<(StatusCode, Json<VersionedTasks>)> {
    let text = clean_task_text(&req.text).map_err(Error::bad_request)?;
    let id = auth::random_id();
    let out = edit_tasks(&state, a.user_id, |tasks| {
        if tasks.len() >= MAX_TASKS {
            return Err(Error::bad_request(format!("au plus {MAX_TASKS} tâches")));
        }
        tasks.push(Task {
            id: id.clone(),
            text: text.clone(),
            done: false,
            for_session: req.for_session,
            created: Utc::now(),
            done_at: None,
        });
        Ok(())
    })
    .await?;
    Ok((StatusCode::CREATED, Json(out)))
}

async fn patch_task(
    State(state): State<AppState>,
    Auth(a): Auth,
    Path(id): Path<String>,
    Json(patch): Json<TaskPatch>,
) -> ApiResult<Json<VersionedTasks>> {
    let text = patch
        .text
        .as_deref()
        .map(clean_task_text)
        .transpose()
        .map_err(Error::bad_request)?;
    let out = edit_tasks(&state, a.user_id, |tasks| {
        let t = tasks
            .iter_mut()
            .find(|t| t.id == id)
            .ok_or_else(|| Error::new(StatusCode::NOT_FOUND, "not_found", "Tâche introuvable"))?;
        if let Some(text) = &text {
            t.text = text.clone();
        }
        if let Some(done) = patch.done {
            t.done = done;
            t.done_at = done.then(Utc::now);
        }
        if let Some(s) = patch.for_session {
            t.for_session = s && !t.done;
        }
        Ok(())
    })
    .await?;
    Ok(Json(out))
}

async fn delete_task(
    State(state): State<AppState>,
    Auth(a): Auth,
    Path(id): Path<String>,
) -> ApiResult<Json<VersionedTasks>> {
    let out = edit_tasks(&state, a.user_id, |tasks| {
        let before = tasks.len();
        tasks.retain(|t| t.id != id);
        if tasks.len() == before {
            return Err(Error::new(
                StatusCode::NOT_FOUND,
                "not_found",
                "Tâche introuvable",
            ));
        }
        Ok(())
    })
    .await?;
    Ok(Json(out))
}

// ------------------------------------------------------------ sessions

pub fn session_view(state: &AppState, d: &DeviceRow) -> SessionView {
    let (status, updated) = state.hub.status(d.user_id, &d.id);
    SessionView {
        device_id: d.id.clone(),
        device_name: d.name.clone(),
        online: state.hub.is_online(d.user_id, &d.id),
        status,
        updated,
    }
}

pub async fn desktops(state: &AppState, user: i64) -> ApiResult<Vec<DeviceRow>> {
    let rows = db::list_devices(&state.db, user).await?;
    Ok(rows
        .into_iter()
        .filter(|d| d.kind == DeviceKind::Desktop)
        .collect())
}

async fn session(State(state): State<AppState>, Auth(a): Auth) -> ApiResult<Json<Vec<SessionView>>> {
    let views = desktops(&state, a.user_id)
        .await?
        .iter()
        .map(|d| session_view(&state, d))
        .collect();
    Ok(Json(views))
}

/// PC visé : celui demandé (s'il appartient au compte), sinon le seul en ligne.
async fn pick_desktop(state: &AppState, user: i64, wanted: Option<String>) -> ApiResult<String> {
    let pcs = desktops(state, user).await?;
    let online: Vec<&DeviceRow> = pcs.iter().filter(|d| state.hub.is_online(user, &d.id)).collect();
    match wanted {
        Some(id) => {
            if !pcs.iter().any(|d| d.id == id) {
                return Err(Error::new(StatusCode::NOT_FOUND, "not_found", "PC introuvable"));
            }
            if !online.iter().any(|d| d.id == id) {
                return Err(Error::new(
                    StatusCode::CONFLICT,
                    "offline",
                    "Ce PC n'est pas connecté",
                ));
            }
            Ok(id)
        }
        None => match online.as_slice() {
            [] => Err(Error::new(
                StatusCode::CONFLICT,
                "no_agent",
                "Aucun PC connecté : lancez « cocon agent » sur votre ordinateur",
            )),
            [one] => Ok(one.id.clone()),
            _ => Err(Error::new(
                StatusCode::CONFLICT,
                "ambiguous",
                "Plusieurs PC sont connectés : précisez device_id",
            )),
        },
    }
}

fn command_error(e: CommandError) -> Error {
    match e {
        CommandError::Offline => Error::new(StatusCode::CONFLICT, "offline", "Le PC s'est déconnecté"),
        CommandError::Timeout => Error::new(
            StatusCode::GATEWAY_TIMEOUT,
            "timeout",
            "Le PC n'a pas répondu à temps",
        ),
    }
}

fn outcome_response(outcome: CommandOutcome) -> ApiResult<Json<CommandOutcome>> {
    match outcome {
        CommandOutcome::Failed { message } => Err(Error::new(StatusCode::CONFLICT, "failed", message)),
        other => Ok(Json(other)),
    }
}

async fn start(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Auth(a): Auth,
    Json(req): Json<StartRequest>,
) -> ApiResult<Json<CommandOutcome>> {
    if req.minutes.is_some_and(|m| !(1..=1440).contains(&m)) {
        return Err(Error::bad_request("durée entre 1 et 1440 minutes"));
    }
    let pc = pick_desktop(&state, a.user_id, req.device_id).await?;
    audit(
        &state,
        Some(a.user_id),
        Some(a.device_id.clone()),
        ip,
        "session_start",
        pc.clone(),
    );
    let outcome = state
        .hub
        .command(a.user_id, &pc, AgentAction::Start { minutes: req.minutes })
        .await
        .map_err(command_error)?;
    outcome_response(outcome)
}

async fn stop(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Auth(a): Auth,
    Json(req): Json<StopRequest>,
) -> ApiResult<Json<CommandOutcome>> {
    if req.confirmation.len() > 500 {
        return Err(Error::bad_request("confirmation trop longue"));
    }
    let pc = pick_desktop(&state, a.user_id, req.device_id).await?;
    audit(
        &state,
        Some(a.user_id),
        Some(a.device_id.clone()),
        ip,
        "session_stop",
        pc.clone(),
    );
    let outcome = state
        .hub
        .command(
            a.user_id,
            &pc,
            AgentAction::Stop {
                confirmation: req.confirmation,
            },
        )
        .await
        .map_err(command_error)?;
    outcome_response(outcome)
}
