//! Interface web : pages (servies par l'API elle-même), inscription,
//! connexion et sécurité du compte.
//!
//! Le navigateur ne voit jamais de jeton : la session tient dans le cookie
//! `__Host-cocon` (`HttpOnly`, `Secure`, `SameSite=Strict`, sans domaine),
//! inaccessible au JavaScript de la page. Les données passent ensuite par
//! les mêmes routes `/v1` que l'application mobile.

use std::net::IpAddr;

use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::Utc;

use crate::auth;
use crate::db;
use crate::protocol::*;
use crate::routes::{self, ApiResult, AppState, Auth, ClientIp, Error, SESSION_COOKIE, audit};

const INDEX: &str = include_str!("../web/index.html");
const APP_JS: &str = include_str!("../web/app.js");
const APP_CSS: &str = include_str!("../web/app.css");
const ICON: &str = include_str!("../web/icon.svg");
// Red Hat Display (SIL Open Font License, voir web/fonts/OFL.txt).
const FONT_LIGHT: &[u8] = include_bytes!("../web/fonts/display-300.otf");
const FONT_REGULAR: &[u8] = include_bytes!("../web/fonts/display-400.otf");
const FONT_MEDIUM: &[u8] = include_bytes!("../web/fonts/display-500.otf");
const FONT_BOLD: &[u8] = include_bytes!("../web/fonts/display-700.otf");

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", get(|| asset("text/html; charset=utf-8", INDEX)))
        .route("/app.js", get(|| asset("text/javascript; charset=utf-8", APP_JS)))
        .route("/app.css", get(|| asset("text/css; charset=utf-8", APP_CSS)))
        .route("/icon.svg", get(|| asset("image/svg+xml", ICON)))
        .route("/fonts/display-300.otf", get(|| font(FONT_LIGHT)))
        .route("/fonts/display-400.otf", get(|| font(FONT_REGULAR)))
        .route("/fonts/display-500.otf", get(|| font(FONT_MEDIUM)))
        .route("/fonts/display-700.otf", get(|| font(FONT_BOLD)))
        .route("/web/info", get(info))
        .route("/web/signup", post(signup))
        .route("/web/login", post(login))
        .route("/web/logout", post(logout))
        .route("/web/password", post(change_password))
        .route("/web/totp/setup", post(totp_setup))
        .route("/web/totp/confirm", post(totp_confirm))
        .route("/web/totp/disable", post(totp_disable))
        .route("/web/account/delete", post(delete_account))
}

async fn asset(content_type: &'static str, body: &'static str) -> Response {
    ([(header::CONTENT_TYPE, content_type)], body).into_response()
}

async fn font(body: &'static [u8]) -> Response {
    ([(header::CONTENT_TYPE, "font/otf")], body).into_response()
}

fn session_cookie(token: &str) -> HeaderValue {
    let v = format!(
        "{SESSION_COOKIE}={token}; Path=/; Max-Age={}; HttpOnly; Secure; SameSite=Strict",
        auth::WEB_TTL.num_seconds()
    );
    HeaderValue::from_str(&v).unwrap_or(HeaderValue::from_static(""))
}

fn clear_cookie() -> HeaderValue {
    HeaderValue::from_static("__Host-cocon=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict")
}

/// « Firefox sur Linux » : nom lisible de l'appareil, pour la liste des sessions.
fn browser_name(headers: &HeaderMap) -> String {
    let ua = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    let browser = [
        ("Firefox/", "Firefox"),
        ("Edg/", "Edge"),
        ("OPR/", "Opera"),
        ("Chrome/", "Chrome"),
        ("Safari/", "Safari"),
    ]
    .iter()
    .find(|(k, _)| ua.contains(k))
    .map_or("Navigateur", |(_, n)| n);
    let os = [
        ("Android", "Android"),
        ("iPhone", "iPhone"),
        ("iPad", "iPad"),
        ("Windows", "Windows"),
        ("Mac OS", "macOS"),
        ("Linux", "Linux"),
    ]
    .iter()
    .find(|(k, _)| ua.contains(k))
    .map(|(_, n)| *n);
    match os {
        Some(os) => format!("{browser} sur {os}"),
        None => browser.to_owned(),
    }
}

/// Ouvre une session web : nouvel appareil « web », cookie.
async fn open_session(state: &AppState, user: &db::UserRow, headers: &HeaderMap) -> ApiResult<Response> {
    let device = auth::random_id();
    db::reset_failures(&state.db, user.id).await?;
    db::create_device(
        &state.db,
        &device,
        user.id,
        &browser_name(headers),
        DeviceKind::Web,
    )
    .await?;
    let token = auth::issue_web_session(&state.db, &device).await?;
    state.hub.publish(user.id, ClientEvent::DevicesChanged);
    let me = Me {
        email: user.email.clone(),
        totp_enabled: user.totp_secret.is_some(),
        device_id: device,
    };
    Ok(([(header::SET_COOKIE, session_cookie(&token))], Json(me)).into_response())
}

async fn info(State(state): State<AppState>) -> Json<WebInfo> {
    Json(WebInfo { signup: state.signup })
}

async fn signup(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    headers: HeaderMap,
    Json(req): Json<SignupRequest>,
) -> ApiResult<Response> {
    if !routes::same_origin(&headers) {
        return Err(Error::new(
            StatusCode::FORBIDDEN,
            "csrf",
            "Requête refusée : origine non autorisée",
        ));
    }
    if state.signup == SignupMode::Closed {
        return Err(Error::new(
            StatusCode::FORBIDDEN,
            "signup_closed",
            "Les inscriptions sont fermées sur ce serveur",
        ));
    }
    if !state.signup_limiter.allow(ip) {
        audit(&state, None, None, ip, "signup_rate_limited", String::new());
        return Err(Error::too_many());
    }
    let email = clean_email(&req.email).map_err(Error::bad_request)?;
    auth::check_password_policy(&req.password).map_err(|e| Error::bad_request(e.to_string()))?;
    if req.password.len() > 1024 {
        return Err(Error::bad_request("mot de passe trop long"));
    }
    let password = req.password.clone();
    let hash = tokio::task::spawn_blocking(move || auth::hash_password(&password))
        .await
        .map_err(|e| anyhow::anyhow!(e))??;

    let created = match state.signup {
        SignupMode::Invite => {
            let code = req.invite.as_deref().map(str::trim).unwrap_or_default();
            if code.is_empty() || code.len() > 200 {
                return Err(Error::new(
                    StatusCode::FORBIDDEN,
                    "invite_required",
                    "Code d'invitation requis",
                ));
            }
            match db::create_user_with_invite(&state.db, &email, &hash, &auth::token_hash(code)).await {
                Ok(Some(id)) => Some(id),
                Ok(None) => {
                    return Err(Error::new(
                        StatusCode::FORBIDDEN,
                        "invalid_invite",
                        "Code d'invitation invalide, expiré ou déjà utilisé",
                    ));
                }
                Err(_) => None,
            }
        }
        _ => db::create_user(&state.db, &email, &hash).await.ok(),
    };
    let Some(id) = created else {
        audit(
            &state,
            None,
            None,
            ip,
            "signup_failed",
            "adresse déjà utilisée".into(),
        );
        return Err(Error::new(
            StatusCode::CONFLICT,
            "email_taken",
            "Un compte existe déjà avec cette adresse",
        ));
    };
    audit(&state, Some(id), None, ip, "signup", email.clone());
    let user = db::user_by_id(&state.db, id)
        .await?
        .ok_or_else(Error::unauthorized)?;
    let mut resp = open_session(&state, &user, &headers).await?;
    *resp.status_mut() = StatusCode::CREATED;
    Ok(resp)
}

async fn login(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    headers: HeaderMap,
    Json(req): Json<WebLogin>,
) -> ApiResult<Response> {
    if !routes::same_origin(&headers) {
        return Err(Error::new(
            StatusCode::FORBIDDEN,
            "csrf",
            "Requête refusée : origine non autorisée",
        ));
    }
    let user = routes::check_credentials(&state, ip, &req.email, &req.password, req.totp.as_deref()).await?;
    audit(
        &state,
        Some(user.id),
        None,
        ip,
        "login_ok",
        browser_name(&headers),
    );
    open_session(&state, &user, &headers).await
}

async fn logout(State(state): State<AppState>, ClientIp(ip): ClientIp, Auth(a): Auth) -> ApiResult<Response> {
    db::revoke_device(&state.db, &a.device_id).await?;
    state.hub.publish(a.user_id, ClientEvent::DevicesChanged);
    audit(
        &state,
        Some(a.user_id),
        Some(a.device_id),
        ip,
        "logout",
        String::new(),
    );
    Ok(([(header::SET_COOKIE, clear_cookie())], StatusCode::NO_CONTENT).into_response())
}

/// Revérifie le mot de passe avant une action sensible (les échecs comptent
/// pour le verrouillage du compte).
async fn confirm_password(state: &AppState, ip: IpAddr, user: &db::UserRow, password: &str) -> ApiResult<()> {
    if !state.login_limiter.allow(ip) {
        return Err(Error::too_many());
    }
    if user.locked_until.is_some_and(|t| t > Utc::now()) {
        return Err(Error::too_many());
    }
    let (password, hash) = (password.to_owned(), user.pw_hash.clone());
    let ok = tokio::task::spawn_blocking(move || auth::verify_password(&password, &hash))
        .await
        .map_err(|e| anyhow::anyhow!(e))?;
    if !ok {
        db::record_failure(&state.db, user.id, auth::MAX_FAILURES, auth::LOCK_FOR).await?;
        audit(
            state,
            Some(user.id),
            None,
            ip,
            "password_check_failed",
            String::new(),
        );
        return Err(Error::new(
            StatusCode::UNAUTHORIZED,
            "invalid_password",
            "Mot de passe incorrect",
        ));
    }
    Ok(())
}

async fn current_user(state: &AppState, a: &auth::Authenticated) -> ApiResult<db::UserRow> {
    db::user_by_id(&state.db, a.user_id)
        .await?
        .ok_or_else(Error::unauthorized)
}

async fn change_password(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Auth(a): Auth,
    Json(req): Json<PasswordChange>,
) -> ApiResult<StatusCode> {
    let user = current_user(&state, &a).await?;
    confirm_password(&state, ip, &user, &req.current).await?;
    auth::check_password_policy(&req.new).map_err(|e| Error::bad_request(e.to_string()))?;
    let new = req.new.clone();
    let hash = tokio::task::spawn_blocking(move || auth::hash_password(&new))
        .await
        .map_err(|e| anyhow::anyhow!(e))??;
    db::set_password(&state.db, user.id, &hash).await?;
    // Tous les autres appareils doivent se reconnecter.
    for d in db::list_devices(&state.db, user.id).await? {
        if d.id != a.device_id {
            db::revoke_device(&state.db, &d.id).await?;
            state.hub.disconnect(user.id, &d.id);
        }
    }
    state.hub.publish(user.id, ClientEvent::DevicesChanged);
    audit(
        &state,
        Some(user.id),
        Some(a.device_id),
        ip,
        "password_changed",
        "autres appareils révoqués".into(),
    );
    Ok(StatusCode::NO_CONTENT)
}

async fn totp_setup(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Auth(a): Auth,
    Json(req): Json<PasswordOnly>,
) -> ApiResult<Json<TotpSetup>> {
    let user = current_user(&state, &a).await?;
    confirm_password(&state, ip, &user, &req.password).await?;
    if user.totp_secret.is_some() {
        return Err(Error::new(
            StatusCode::CONFLICT,
            "totp_enabled",
            "La double authentification est déjà active",
        ));
    }
    let (secret, url) = auth::new_totp(&user.email)?;
    let qr_png = auth::totp_qr(&secret, &user.email)?;
    db::set_totp_pending(&state.db, user.id, Some(&secret)).await?;
    Ok(Json(TotpSetup { secret, url, qr_png }))
}

async fn totp_confirm(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Auth(a): Auth,
    Json(req): Json<TotpCode>,
) -> ApiResult<StatusCode> {
    let user = current_user(&state, &a).await?;
    let Some(pending) = &user.totp_pending else {
        return Err(Error::bad_request("aucune activation en cours"));
    };
    let Some(step) = auth::check_totp(pending, &user.email, &req.code, 0) else {
        return Err(Error::new(
            StatusCode::UNAUTHORIZED,
            "invalid_totp",
            "Code invalide : vérifiez l'heure du téléphone",
        ));
    };
    db::confirm_totp(&state.db, user.id, step).await?;
    audit(
        &state,
        Some(user.id),
        Some(a.device_id),
        ip,
        "totp_enabled",
        String::new(),
    );
    Ok(StatusCode::NO_CONTENT)
}

async fn totp_disable(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Auth(a): Auth,
    Json(req): Json<TotpCode>,
) -> ApiResult<StatusCode> {
    let user = current_user(&state, &a).await?;
    confirm_password(&state, ip, &user, req.password.as_deref().unwrap_or_default()).await?;
    let Some(secret) = &user.totp_secret else {
        return Ok(StatusCode::NO_CONTENT);
    };
    let accepted = match auth::check_totp(secret, &user.email, &req.code, user.totp_last_step) {
        Some(step) => db::use_totp_step(&state.db, user.id, step).await?,
        None => false,
    };
    if !accepted {
        return Err(Error::new(
            StatusCode::UNAUTHORIZED,
            "invalid_totp",
            "Code de double authentification invalide",
        ));
    }
    db::set_totp(&state.db, user.id, None).await?;
    audit(
        &state,
        Some(user.id),
        Some(a.device_id),
        ip,
        "totp_disabled",
        String::new(),
    );
    Ok(StatusCode::NO_CONTENT)
}

async fn delete_account(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Auth(a): Auth,
    Json(req): Json<PasswordOnly>,
) -> ApiResult<Response> {
    let user = current_user(&state, &a).await?;
    confirm_password(&state, ip, &user, &req.password).await?;
    for d in db::list_devices(&state.db, user.id).await? {
        state.hub.disconnect(user.id, &d.id);
    }
    db::delete_user(&state.db, user.id).await?;
    audit(&state, None, None, ip, "account_deleted", user.email.clone());
    Ok(([(header::SET_COOKIE, clear_cookie())], StatusCode::NO_CONTENT).into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn readable_device_names() {
        let h = |ua: &str| {
            let mut m = HeaderMap::new();
            m.insert(header::USER_AGENT, ua.parse().unwrap());
            browser_name(&m)
        };
        assert_eq!(
            h("Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0"),
            "Firefox sur Linux"
        );
        assert_eq!(
            h("Mozilla/5.0 (Linux; Android 15) AppleWebKit/537.36 Chrome/140.0 Mobile Safari/537.36"),
            "Chrome sur Android"
        );
        assert_eq!(h(""), "Navigateur");
    }
}
