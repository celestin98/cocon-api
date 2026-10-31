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
        .route("/web/signup/verify", post(verify_email))
        .route("/web/signup/resend", post(resend_code))
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

    // Inscription libre : compte en attente, code à 6 chiffres par e-mail.
    if let (SignupMode::Open, Some(mailer)) = (state.signup, state.mailer.clone()) {
        let Some(id) = db::create_unverified_user(&state.db, &email, &hash).await? else {
            audit(
                &state,
                None,
                None,
                ip,
                "signup_failed",
                "adresse déjà utilisée".into(),
            );
            return Err(email_taken());
        };
        if let Err(e) = send_code(&state, &mailer, id, &email).await {
            // Sans code, le compte ne pourrait jamais être confirmé.
            tracing::warn!("code de vérification non envoyé à {email} : {e:#}");
            db::delete_user(&state.db, id).await?;
            audit(&state, None, None, ip, "signup_mail_failed", email);
            return Err(mail_failed());
        }
        audit(&state, Some(id), None, ip, "signup_pending", email.clone());
        return Ok((StatusCode::ACCEPTED, Json(SignupPending { email, verify: true })).into_response());
    }

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
        return Err(email_taken());
    };
    audit(&state, Some(id), None, ip, "signup", email.clone());
    let user = db::user_by_id(&state.db, id)
        .await?
        .ok_or_else(Error::unauthorized)?;
    let mut resp = open_session(&state, &user, &headers).await?;
    *resp.status_mut() = StatusCode::CREATED;
    Ok(resp)
}

fn email_taken() -> Error {
    Error::new(
        StatusCode::CONFLICT,
        "email_taken",
        "Un compte existe déjà avec cette adresse",
    )
}

fn mail_failed() -> Error {
    Error::new(
        StatusCode::SERVICE_UNAVAILABLE,
        "mail_failed",
        "Impossible d'envoyer le code de confirmation pour le moment. Réessayez plus tard.",
    )
}

fn same_origin_or_403(headers: &HeaderMap) -> ApiResult<()> {
    if routes::same_origin(headers) {
        Ok(())
    } else {
        Err(Error::new(
            StatusCode::FORBIDDEN,
            "csrf",
            "Requête refusée : origine non autorisée",
        ))
    }
}

/// Nouveau code pour un compte en attente : envoyé, puis enregistré (haché).
/// Un envoi raté ne compte pas dans le plafond et laisse l'ancien code
/// valable. `Ok(false)` si le nombre maximal d'envois est atteint.
async fn send_code(
    state: &AppState,
    mailer: &crate::mail::Mailer,
    user: i64,
    email: &str,
) -> anyhow::Result<bool> {
    if db::email_code_sends(&state.db, user).await? >= auth::EMAIL_CODE_MAX_SENDS {
        return Ok(false);
    }
    let code = auth::new_email_code();
    mailer.send_signup_code(email, &code).await?;
    let expires = Utc::now() + auth::EMAIL_CODE_TTL;
    if !db::set_email_code(
        &state.db,
        user,
        &auth::email_code_hash(user, &code),
        expires,
        auth::EMAIL_CODE_MAX_SENDS,
    )
    .await?
    {
        return Ok(false);
    }
    tracing::info!("code de vérification envoyé à {email}");
    Ok(true)
}

fn code_limit() -> Error {
    Error::new(
        StatusCode::FORBIDDEN,
        "code_limit",
        "Trop de codes ont été envoyés à cette adresse. L'inscription en attente sera \
         effacée sous 24 heures : vous pourrez alors recommencer.",
    )
}

/// Renvoie un code si le précédent date d'au moins une minute.
async fn resend_if_due(state: &AppState, user: &db::UserRow) -> ApiResult<()> {
    let Some(mailer) = state.mailer.clone() else {
        return Ok(());
    };
    let due = db::email_code_sent(&state.db, user.id)
        .await?
        .is_none_or(|sent| Utc::now() - sent >= auth::EMAIL_CODE_RESEND_AFTER);
    if !due {
        tracing::info!("code pour {} non renvoyé : le précédent a moins d'une minute", user.email);
        return Ok(());
    }
    match send_code(state, &mailer, user.id, &user.email).await {
        Ok(true) => Ok(()),
        Ok(false) => {
            tracing::warn!("code pour {} non renvoyé : plafond d'envois atteint", user.email);
            Err(code_limit())
        }
        Err(e) => {
            tracing::warn!("code de vérification non envoyé à {} : {e:#}", user.email);
            Err(mail_failed())
        }
    }
}

/// Étape 2 de l'inscription : le code reçu confirme l'adresse et ouvre la session.
async fn verify_email(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    headers: HeaderMap,
    Json(req): Json<VerifyEmailRequest>,
) -> ApiResult<Response> {
    same_origin_or_403(&headers)?;
    if !state.code_limiter.allow(ip) {
        return Err(Error::too_many());
    }
    let Some(code) = auth::clean_email_code(&req.code) else {
        return Err(Error::new(
            StatusCode::BAD_REQUEST,
            "invalid_code",
            "Le code se compose de 6 chiffres",
        ));
    };
    let expired = || {
        Error::new(
            StatusCode::BAD_REQUEST,
            "code_expired",
            "Ce code a expiré ou a été trop souvent mal saisi : demandez-en un nouveau",
        )
    };
    let email = req.email.trim().to_lowercase();
    // Compte inconnu ou déjà confirmé : même réponse qu'un code périmé.
    let Some(user) = db::user_by_email(&state.db, &email)
        .await?
        .filter(|u| !u.email_verified)
    else {
        return Err(expired());
    };
    match db::check_email_code(
        &state.db,
        user.id,
        &auth::email_code_hash(user.id, &code),
        auth::EMAIL_CODE_MAX_ATTEMPTS,
    )
    .await?
    {
        db::EmailCodeCheck::Verified => {
            audit(
                &state,
                Some(user.id),
                None,
                ip,
                "email_verified",
                user.email.clone(),
            );
            let mut resp = open_session(&state, &user, &headers).await?;
            *resp.status_mut() = StatusCode::CREATED;
            Ok(resp)
        }
        db::EmailCodeCheck::Invalid => {
            audit(
                &state,
                Some(user.id),
                None,
                ip,
                "email_code_invalid",
                String::new(),
            );
            Err(Error::new(
                StatusCode::BAD_REQUEST,
                "invalid_code",
                "Code incorrect",
            ))
        }
        db::EmailCodeCheck::Expired => Err(expired()),
    }
}

/// « Renvoyer le code » : toujours 204, que le compte existe ou non.
async fn resend_code(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    headers: HeaderMap,
    Json(req): Json<ResendCodeRequest>,
) -> ApiResult<StatusCode> {
    same_origin_or_403(&headers)?;
    if !state.code_limiter.allow(ip) {
        return Err(Error::too_many());
    }
    let email = req.email.trim().to_lowercase();
    if let Some(user) = db::user_by_email(&state.db, &email)
        .await?
        .filter(|u| !u.email_verified)
    {
        resend_if_due(&state, &user).await?;
    }
    Ok(StatusCode::NO_CONTENT)
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
    let user =
        match routes::check_credentials(&state, ip, &req.email, &req.password, req.totp.as_deref()).await {
            Ok(user) => user,
            Err(e) if e.code() == "email_unverified" => {
                // Bon mot de passe, adresse pas encore confirmée : nouveau code,
                // l'interface passe à l'étape de vérification.
                if let Some(user) = db::user_by_email(&state.db, &req.email.trim().to_lowercase()).await? {
                    resend_if_due(&state, &user).await?;
                }
                return Err(e);
            }
            Err(e) => return Err(e),
        };
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
