//! Tests de bout en bout : routeur réel, PostgreSQL (`TEST_DATABASE_URL`,
//! un schéma jetable par test). Sans base de test, ces tests sont ignorés.

use std::net::SocketAddr;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use futures_util::{SinkExt, StreamExt};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tokio_tungstenite::tungstenite::{self, client::IntoClientRequest};
use tower::ServiceExt;

use crate::db::{self, Db};
use crate::{auth, routes};

const EMAIL: &str = "moi@exemple.org";
const PASSWORD: &str = "un mot de passe assez long";

async fn setup() -> Option<(Router, Db)> {
    let Some(db) = Db::test().await else {
        eprintln!("TEST_DATABASE_URL absent : test ignoré");
        return None;
    };
    let hash = auth::hash_password(PASSWORD).unwrap();
    db::create_user(&db, EMAIL, &hash).await.unwrap();
    Some((routes::router(routes::AppState::new(db.clone())), db))
}

async fn call(
    app: &Router,
    method: &str,
    uri: &str,
    token: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Value) {
    call_from(app, method, uri, token, body, "192.0.2.10").await
}

/// Requête « venant » de `ip` (via X-Forwarded-For : le pair des tests est
/// la boucle locale, comme un reverse proxy).
async fn call_from(
    app: &Router,
    method: &str,
    uri: &str,
    token: Option<&str>,
    body: Option<Value>,
    ip: &str,
) -> (StatusCode, Value) {
    let mut req = Request::builder()
        .method(method)
        .uri(uri)
        .header("x-forwarded-for", ip);
    if let Some(t) = token {
        req = req.header("authorization", format!("Bearer {t}"));
    }
    let req = match body {
        Some(b) => req
            .header("content-type", "application/json")
            .body(Body::from(b.to_string())),
        None => req.body(Body::empty()),
    }
    .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let v = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, v)
}

fn login_body(password: &str, kind: &str) -> Value {
    json!({"email": EMAIL, "password": password, "device_name": "Test", "device_kind": kind})
}

async fn login(app: &Router, kind: &str) -> Value {
    let (s, v) = call(
        app,
        "POST",
        "/v1/auth/login",
        None,
        Some(login_body(PASSWORD, kind)),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    v
}

fn tok(v: &Value, field: &str) -> String {
    v[field].as_str().unwrap().to_owned()
}

#[tokio::test]
async fn health_and_security_headers() {
    let Some((app, _)) = setup().await else {
        return;
    };
    let resp = app
        .clone()
        .oneshot(Request::get("/health").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let h = resp.headers();
    assert_eq!(h["x-content-type-options"], "nosniff");
    assert_eq!(h["cache-control"], "no-store");
    assert_eq!(h["x-frame-options"], "DENY");
}

#[tokio::test]
async fn login_and_access_control() {
    let Some((app, _)) = setup().await else {
        return;
    };
    // Mauvais mot de passe et compte inconnu : même réponse.
    let (s1, v1) = call(
        &app,
        "POST",
        "/v1/auth/login",
        None,
        Some(login_body("faux faux faux", "mobile")),
    )
    .await;
    let mut unknown = login_body(PASSWORD, "mobile");
    unknown["email"] = json!("inconnu@exemple.org");
    let (s2, v2) = call(&app, "POST", "/v1/auth/login", None, Some(unknown)).await;
    assert_eq!((s1, s2), (StatusCode::UNAUTHORIZED, StatusCode::UNAUTHORIZED));
    assert_eq!(v1, v2);

    // Champs inconnus refusés.
    let mut extra = login_body(PASSWORD, "mobile");
    extra["admin"] = json!(true);
    let (s, _) = call(&app, "POST", "/v1/auth/login", None, Some(extra)).await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);

    let pair = login(&app, "mobile").await;
    let access = tok(&pair, "access_token");
    let (s, me) = call(&app, "GET", "/v1/me", Some(&access), None).await;
    assert_eq!((s, me["email"].as_str()), (StatusCode::OK, Some(EMAIL)));
    assert_eq!(
        call(&app, "GET", "/v1/me", None, None).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        call(&app, "GET", "/v1/me", Some("ca_faux"), None).await.0,
        StatusCode::UNAUTHORIZED
    );
    // Un jeton de renouvellement n'ouvre pas l'API.
    let refresh = tok(&pair, "refresh_token");
    assert_eq!(
        call(&app, "GET", "/v1/me", Some(&refresh), None).await.0,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn refresh_rotation_detects_reuse() {
    let Some((app, _)) = setup().await else {
        return;
    };
    let pair = login(&app, "desktop").await;
    let r1 = tok(&pair, "refresh_token");
    let (s, pair2) = call(
        &app,
        "POST",
        "/v1/auth/refresh",
        None,
        Some(json!({"refresh_token": r1})),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let access2 = tok(&pair2, "access_token");
    assert_eq!(
        call(&app, "GET", "/v1/me", Some(&access2), None).await.0,
        StatusCode::OK
    );

    // Rejeu de l'ancien jeton : l'appareil est révoqué, même le nouveau accès tombe.
    let (s, _) = call(
        &app,
        "POST",
        "/v1/auth/refresh",
        None,
        Some(json!({"refresh_token": r1})),
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert_eq!(
        call(&app, "GET", "/v1/me", Some(&access2), None).await.0,
        StatusCode::UNAUTHORIZED
    );
    let r2 = tok(&pair2, "refresh_token");
    let (s, _) = call(
        &app,
        "POST",
        "/v1/auth/refresh",
        None,
        Some(json!({"refresh_token": r2})),
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn account_lockout_and_ip_rate_limit() {
    let Some((app, _)) = setup().await else {
        return;
    };
    for _ in 0..auth::MAX_FAILURES {
        let (s, _) = call(
            &app,
            "POST",
            "/v1/auth/login",
            None,
            Some(login_body("mauvais mot de passe", "mobile")),
        )
        .await;
        assert_eq!(s, StatusCode::UNAUTHORIZED);
    }
    // Compte verrouillé : même le bon mot de passe est refusé.
    let (s, v) = call(
        &app,
        "POST",
        "/v1/auth/login",
        None,
        Some(login_body(PASSWORD, "mobile")),
    )
    .await;
    assert_eq!(
        (s, v["error"].as_str()),
        (StatusCode::TOO_MANY_REQUESTS, Some("too_many_attempts"))
    );

    // Limite par adresse IP (10 tentatives / 10 min), indépendante du compte.
    let Some((app, _)) = setup().await else {
        return;
    };
    let body = || {
        let mut b = login_body("x", "mobile");
        b["email"] = json!("personne@exemple.org");
        Some(b)
    };
    for _ in 0..10 {
        call_from(&app, "POST", "/v1/auth/login", None, body(), "198.51.100.1").await;
    }
    let (s, _) = call_from(&app, "POST", "/v1/auth/login", None, body(), "198.51.100.1").await;
    assert_eq!(s, StatusCode::TOO_MANY_REQUESTS);
    let (s, _) = call_from(&app, "POST", "/v1/auth/login", None, body(), "198.51.100.2").await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn totp_required_and_single_use() {
    let Some((app, db)) = setup().await else {
        return;
    };
    let (secret, _) = auth::new_totp(EMAIL).unwrap();
    let u = db::user_by_email(&db, EMAIL).await.unwrap().unwrap();
    db::set_totp(&db, u.id, Some(&secret)).await.unwrap();
    let (s, v) = call(
        &app,
        "POST",
        "/v1/auth/login",
        None,
        Some(login_body(PASSWORD, "mobile")),
    )
    .await;
    assert_eq!(
        (s, v["error"].as_str()),
        (StatusCode::UNAUTHORIZED, Some("totp_required"))
    );

    let code = totp_rs::Builder::new()
        .with_secret(totp_rs::Secret::try_from_base32(&secret).unwrap())
        .with_account_name(EMAIL)
        .with_issuer(Some("Cocon"))
        .build()
        .unwrap()
        .generate(chrono::Utc::now().timestamp() as u64)
        .to_string();
    let mut body = login_body(PASSWORD, "mobile");
    body["totp"] = json!(code);
    assert_eq!(
        call(&app, "POST", "/v1/auth/login", None, Some(body.clone()))
            .await
            .0,
        StatusCode::OK
    );
    // Même code une seconde fois : refusé.
    let (s, v) = call(&app, "POST", "/v1/auth/login", None, Some(body)).await;
    assert_eq!(
        (s, v["error"].as_str()),
        (StatusCode::UNAUTHORIZED, Some("invalid_totp"))
    );
}

#[tokio::test]
async fn config_is_versioned_and_validated() {
    let Some((app, _)) = setup().await else {
        return;
    };
    let t = tok(&login(&app, "mobile").await, "access_token");
    let (s, v) = call(&app, "GET", "/v1/config", Some(&t), None).await;
    assert_eq!((s, v["version"].as_u64()), (StatusCode::OK, Some(0)));

    let cfg = json!({"session": {"default_minutes": 50}});
    let (s, v) = call(
        &app,
        "PUT",
        "/v1/config",
        Some(&t),
        Some(json!({"version": 0, "config": cfg})),
    )
    .await;
    assert_eq!((s, v["version"].as_u64()), (StatusCode::OK, Some(1)));
    let (s, v) = call(
        &app,
        "PUT",
        "/v1/config",
        Some(&t),
        Some(json!({"version": 0, "config": cfg})),
    )
    .await;
    assert_eq!((s, v["error"].as_str()), (StatusCode::CONFLICT, Some("conflict")));
    let (s, _) = call(
        &app,
        "PUT",
        "/v1/config",
        Some(&t),
        Some(json!({"version": 1, "config": [1, 2]})),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);

    // Corps trop gros : refusé avant même d'être lu en entier.
    let huge = json!({"version": 1, "config": {"x": "a".repeat(300 * 1024)}});
    assert_eq!(
        call(&app, "PUT", "/v1/config", Some(&t), Some(huge)).await.0,
        StatusCode::PAYLOAD_TOO_LARGE
    );
}

#[tokio::test]
async fn tasks_crud() {
    let Some((app, _)) = setup().await else {
        return;
    };
    let t = tok(&login(&app, "mobile").await, "access_token");
    let (s, v) = call(
        &app,
        "POST",
        "/v1/tasks",
        Some(&t),
        Some(json!({"text": "  Finir   le chapitre ", "for_session": true})),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED);
    let task = &v["tasks"][0];
    assert_eq!(task["text"], "Finir le chapitre");
    let id = task["id"].as_str().unwrap().to_owned();

    let (s, v) = call(
        &app,
        "PATCH",
        &format!("/v1/tasks/{id}"),
        Some(&t),
        Some(json!({"done": true})),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["tasks"][0]["done"], true);
    assert_eq!(
        v["tasks"][0]["for_session"], false,
        "terminée : plus pour la session"
    );
    assert!(v["tasks"][0]["done_at"].is_string());

    assert_eq!(
        call(
            &app,
            "PATCH",
            "/v1/tasks/inconnue",
            Some(&t),
            Some(json!({"done": true}))
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        call(&app, "POST", "/v1/tasks", Some(&t), Some(json!({"text": "   "})))
            .await
            .0,
        StatusCode::BAD_REQUEST
    );
    let (s, v) = call(&app, "DELETE", &format!("/v1/tasks/{id}"), Some(&t), None).await;
    assert_eq!((s, v["tasks"].as_array().unwrap().len()), (StatusCode::OK, 0));

    let dup = json!({"version": v["version"], "tasks": [
        {"id": "a", "text": "x", "created": "2026-10-31T00:00:00Z"},
        {"id": "a", "text": "y", "created": "2026-10-31T00:00:00Z"}]});
    assert_eq!(
        call(&app, "PUT", "/v1/tasks", Some(&t), Some(dup)).await.0,
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn devices_are_isolated_and_revocable() {
    let Some((app, db)) = setup().await else {
        return;
    };
    let phone = login(&app, "mobile").await;
    let pc = login(&app, "desktop").await;
    let (pt, pct) = (tok(&phone, "access_token"), tok(&pc, "access_token"));
    let (s, list) = call(&app, "GET", "/v1/devices", Some(&pt), None).await;
    assert_eq!((s, list.as_array().unwrap().len()), (StatusCode::OK, 2));

    // Un appareil d'un autre compte est introuvable.
    let u = db::create_user(&db, "autre@exemple.org", "h").await.unwrap();
    db::create_device(&db, "etranger", u, "PC", crate::protocol::DeviceKind::Desktop)
        .await
        .unwrap();
    let (s, _) = call(&app, "DELETE", "/v1/devices/etranger", Some(&pt), None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);

    // Révoquer le PC depuis le téléphone le déconnecte.
    let (s, _) = call(
        &app,
        "DELETE",
        &format!("/v1/devices/{}", tok(&pc, "device_id")),
        Some(&pt),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    assert_eq!(
        call(&app, "GET", "/v1/me", Some(&pct), None).await.0,
        StatusCode::UNAUTHORIZED
    );

    // Sans PC connecté, démarrer une session échoue proprement.
    let (s, v) = call(&app, "POST", "/v1/session/start", Some(&pt), Some(json!({}))).await;
    assert_eq!((s, v["error"].as_str()), (StatusCode::CONFLICT, Some("no_agent")));
    assert_eq!(
        call(
            &app,
            "POST",
            "/v1/session/start",
            Some(&pt),
            Some(json!({"minutes": 0}))
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
}

// ------------------------------------------------------------ temps réel

async fn spawn_server(app: Router) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
            .await
            .unwrap();
    });
    addr
}

type Ws = tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

async fn ws_connect(addr: SocketAddr, path: &str, token: &str) -> Result<Ws, tungstenite::Error> {
    let mut req = format!("ws://{addr}{path}").into_client_request().unwrap();
    req.headers_mut()
        .insert("authorization", format!("Bearer {token}").parse().unwrap());
    tokio_tungstenite::connect_async(req).await.map(|(ws, _)| ws)
}

async fn next_json(ws: &mut Ws) -> Value {
    loop {
        let msg = tokio::time::timeout(std::time::Duration::from_secs(5), ws.next())
            .await
            .expect("message attendu")
            .unwrap()
            .unwrap();
        if let tungstenite::Message::Text(t) = msg {
            return serde_json::from_str(&t).unwrap();
        }
    }
}

async fn http(addr: SocketAddr, method: &str, path: &str, token: &str, body: Value) -> (u16, Value) {
    // Petit client HTTP/1.1 minimal (évite une dépendance de plus).
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
    let body = body.to_string();
    let req = format!(
        "{method} {path} HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {token}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    s.write_all(req.as_bytes()).await.unwrap();
    let mut out = String::new();
    s.read_to_string(&mut out).await.unwrap();
    let status = out[9..12].parse().unwrap();
    let json = out
        .split("\r\n\r\n")
        .nth(1)
        .and_then(|b| serde_json::from_str(b).ok())
        .unwrap_or(Value::Null);
    (status, json)
}

#[tokio::test]
async fn agent_relays_commands_and_status_in_real_time() {
    let Some((app, _)) = setup().await else {
        return;
    };
    let addr = spawn_server(app.clone()).await;
    let pc = login(&app, "desktop").await;
    let phone = login(&app, "mobile").await;
    let (pct, pt) = (tok(&pc, "access_token"), tok(&phone, "access_token"));

    // Le canal du connecteur est réservé aux PC, et exige un jeton valide.
    assert!(ws_connect(addr, "/v1/agent", &pt).await.is_err());
    assert!(ws_connect(addr, "/v1/agent", "ca_faux").await.is_err());

    let mut events = ws_connect(addr, "/v1/events", &pt).await.unwrap();
    let mut agent = ws_connect(addr, "/v1/agent", &pct).await.unwrap();
    // Le PC propose sa configuration locale (serveur vide) : acceptée.
    agent
        .send(tungstenite::Message::Text(
            json!({"type": "hello", "config_version": 0, "tasks_version": 0, "config": {"session": {}}})
                .to_string()
                .into(),
        ))
        .await
        .unwrap();
    let accepted = next_json(&mut agent).await;
    assert_eq!(accepted, json!({"type": "config_accepted", "version": 1}));

    // L'état de la session arrive en temps réel sur le téléphone.
    agent
        .send(tungstenite::Message::Text(
            json!({"type": "status", "status": {"active": true, "phase": "Concentration"}})
                .to_string()
                .into(),
        ))
        .await
        .unwrap();
    loop {
        let ev = next_json(&mut events).await;
        if ev["type"] == "session" && ev["status"]["phase"] == "Concentration" {
            assert_eq!(ev["online"], true);
            break;
        }
    }

    // Arrêt demandé depuis le téléphone : relayé au PC, réponse rapportée.
    let stop = tokio::spawn(async move { http(addr, "POST", "/v1/session/stop", &pt, json!({})).await });
    let cmd = next_json(&mut agent).await;
    assert_eq!(cmd["type"], "command");
    assert_eq!(cmd["action"], json!({"type": "stop", "confirmation": ""}));
    agent
        .send(tungstenite::Message::Text(
            json!({"type": "result", "id": cmd["id"], "outcome":
                   {"outcome": "stop", "reply": {"result": "need_hold", "detail": 3}}})
            .to_string()
            .into(),
        ))
        .await
        .unwrap();
    let (status, body) = stop.await.unwrap();
    assert_eq!(status, 200);
    assert_eq!(body["reply"]["result"], "need_hold");

    // Révocation du PC : son canal est fermé par le serveur.
    let (s, _) = http(
        addr,
        "DELETE",
        &format!("/v1/devices/{}", tok(&pc, "device_id")),
        &tok(&phone, "access_token"),
        json!({}),
    )
    .await;
    assert_eq!(s, 204);
    let end = tokio::time::timeout(std::time::Duration::from_secs(5), agent.next())
        .await
        .unwrap();
    assert!(matches!(
        end,
        Some(Ok(tungstenite::Message::Close(_))) | None | Some(Err(_))
    ));
}

// ------------------------------------------------------------ hydratation

async fn next_of_type(ws: &mut Ws, kind: &str) -> Value {
    loop {
        let v = next_json(ws).await;
        if v["type"] == kind {
            return v;
        }
    }
}

#[tokio::test]
async fn hydration_reminders_are_sent_once_and_acknowledged_everywhere() {
    let Some(db) = Db::test().await else {
        eprintln!("TEST_DATABASE_URL absent : test ignoré");
        return;
    };
    let hash = auth::hash_password(PASSWORD).unwrap();
    db::create_user(&db, EMAIL, &hash).await.unwrap();
    let state = routes::AppState::new(db.clone());
    let app = routes::router(state.clone());
    let addr = spawn_server(app.clone()).await;
    let pc = login(&app, "desktop").await;
    let phone = login(&app, "mobile").await;
    let (pct, pt) = (tok(&pc, "access_token"), tok(&phone, "access_token"));

    // Par défaut : désactivé, aucun rappel prévu.
    let (s, v) = call(&app, "GET", "/v1/hydration", Some(&pt), None).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(
        (v["settings"]["enabled"].as_bool(), v["today"].as_u64()),
        (Some(false), Some(0))
    );
    assert!(v["next_reminder"].is_null());

    // Réglages validés côté serveur.
    let now = chrono::Utc::now();
    let hhmm = |d: chrono::Duration| (now + d).format("%H:%M").to_string();
    let settings = json!({
        "enabled": true, "interval_minutes": 15, "goal": 8, "timezone": "UTC",
        // Plage autour de maintenant (traverse minuit au besoin).
        "start": hhmm(chrono::Duration::hours(-1)), "end": hhmm(chrono::Duration::hours(3)),
    });
    let mut bad = settings.clone();
    bad["interval_minutes"] = json!(5);
    let (s, _) = call(&app, "PUT", "/v1/hydration", Some(&pt), Some(bad)).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let mut extra = settings.clone();
    extra["sound"] = json!(true);
    let (s, _) = call(&app, "PUT", "/v1/hydration", Some(&pt), Some(extra)).await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);
    let (s, v) = call(&app, "PUT", "/v1/hydration", Some(&pt), Some(settings)).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let next: chrono::DateTime<chrono::Utc> = serde_json::from_value(v["next_reminder"].clone()).unwrap();
    assert!(
        (next - now - chrono::Duration::minutes(15)).num_seconds().abs() < 30,
        "{next}"
    );

    let mut events = ws_connect(addr, "/v1/events", &pt).await.unwrap();
    let mut agent = ws_connect(addr, "/v1/agent", &pct).await.unwrap();
    // Le PC est enregistré dès qu'il apparaît en ligne pour le téléphone.
    loop {
        let ev = next_of_type(&mut events, "session").await;
        if ev["online"] == true {
            break;
        }
    }

    // Rien n'est dû avant l'heure ; à l'heure, un seul envoi.
    assert_eq!(crate::hydration::tick(&state, now).await.unwrap(), 0);
    let later = now + chrono::Duration::minutes(16);
    assert_eq!(crate::hydration::tick(&state, later).await.unwrap(), 1);
    assert_eq!(crate::hydration::tick(&state, later).await.unwrap(), 0);
    let r = next_of_type(&mut agent, "hydration_reminder").await;
    assert_eq!(r, json!({"type": "hydration_reminder", "today": 0, "goal": 8}));
    let r = next_of_type(&mut events, "hydration_reminder").await;
    assert_eq!(r["goal"], 8);

    // « J'ai bu » depuis la notification du PC : compté, et signalé partout.
    agent
        .send(tungstenite::Message::Text(
            json!({"type": "hydration_drink"}).to_string().into(),
        ))
        .await
        .unwrap();
    assert_eq!(
        next_of_type(&mut agent, "hydration_acknowledged").await["type"],
        "hydration_acknowledged"
    );
    // (Le premier « hydration_changed » suit le rappel, compteur encore à 0.)
    let changed = loop {
        let ev = next_of_type(&mut events, "hydration_changed").await;
        if ev["today"] == 1 {
            break ev;
        }
    };
    assert!(changed["last_drink"].is_string());

    // Un verre compté par erreur s'annule.
    let (s, v) = call(&app, "DELETE", "/v1/hydration/drink", Some(&pt), None).await;
    assert_eq!((s, v["today"].as_u64()), (StatusCode::OK, Some(0)));

    // Garde-fou : pas plus de 60 verres par jour.
    for _ in 0..crate::hydration::MAX_DRINKS_PER_DAY {
        let (s, _) = call(&app, "POST", "/v1/hydration/drink", Some(&pt), None).await;
        assert_eq!(s, StatusCode::OK);
    }
    let (s, v) = call(&app, "POST", "/v1/hydration/drink", Some(&pt), None).await;
    assert_eq!(
        (s, v["error"].as_str()),
        (StatusCode::TOO_MANY_REQUESTS, Some("limit"))
    );

    // Désactivé : plus aucun rappel.
    let (_, mut v) = call(&app, "GET", "/v1/hydration", Some(&pt), None).await;
    v["settings"]["enabled"] = json!(false);
    let (s, v) = call(
        &app,
        "PUT",
        "/v1/hydration",
        Some(&pt),
        Some(v["settings"].clone()),
    )
    .await;
    assert_eq!((s, v["next_reminder"].is_null()), (StatusCode::OK, true));
    let much_later = now + chrono::Duration::hours(2);
    assert_eq!(crate::hydration::tick(&state, much_later).await.unwrap(), 0);
}

// ------------------------------------------------------------ interface web

const ORIGIN: &str = "https://cocon.exemple.org";
const HOST: &str = "cocon.exemple.org";

struct WebResp {
    status: StatusCode,
    cookie: Option<String>,
    set_cookie: String,
    json: Value,
}

/// Requête de navigateur : cookie, en-tête Origin, en-tête anti-CSRF.
async fn web(
    app: &Router,
    method: &str,
    uri: &str,
    cookie: Option<&str>,
    body: Option<Value>,
    origin: Option<&str>,
    csrf: bool,
) -> WebResp {
    let mut req = Request::builder()
        .method(method)
        .uri(uri)
        .header("host", HOST)
        .header("x-forwarded-for", "192.0.2.50")
        .header("user-agent", "Mozilla/5.0 (X11; Linux x86_64) Firefox/140.0");
    if let Some(o) = origin {
        req = req.header("origin", o);
    }
    if csrf {
        req = req.header("x-cocon-csrf", "1");
    }
    if let Some(c) = cookie {
        req = req.header("cookie", format!("autre=1; {}={c}", routes::SESSION_COOKIE));
    }
    let req = match body {
        Some(b) => req
            .header("content-type", "application/json")
            .body(Body::from(b.to_string())),
        None => req.body(Body::empty()),
    }
    .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let set_cookie = resp
        .headers()
        .get("set-cookie")
        .map(|v| v.to_str().unwrap().to_owned())
        .unwrap_or_default();
    let cookie = set_cookie
        .strip_prefix(&format!("{}=", routes::SESSION_COOKIE))
        .and_then(|v| v.split(';').next())
        .filter(|v| !v.is_empty())
        .map(str::to_owned);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    WebResp {
        status,
        cookie,
        set_cookie,
        json: serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    }
}

fn signup_body(email: &str) -> Value {
    json!({"email": email, "password": "une phrase de passe solide"})
}

#[tokio::test]
async fn web_pages_are_served_with_strict_csp() {
    let Some((app, _)) = setup().await else {
        return;
    };
    let resp = app
        .clone()
        .oneshot(Request::get("/").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let csp = resp.headers()["content-security-policy"]
        .to_str()
        .unwrap()
        .to_owned();
    assert!(
        csp.contains("script-src 'self'") && !csp.contains("unsafe-inline"),
        "{csp}"
    );
    for path in ["/app.js", "/app.css", "/icon.svg"] {
        let r = app
            .clone()
            .oneshot(Request::get(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK, "{path}");
    }
}

#[tokio::test]
async fn web_signup_sets_a_locked_down_cookie() {
    let Some((app, _)) = setup().await else {
        return;
    };
    // Sans en-tête Origin (requête forgée hors navigateur) : refusée.
    let r = web(
        &app,
        "POST",
        "/web/signup",
        None,
        Some(signup_body("neuf@exemple.org")),
        None,
        false,
    )
    .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    // Mot de passe trop court, adresse invalide.
    let weak = json!({"email": "neuf@exemple.org", "password": "court"});
    assert_eq!(
        web(&app, "POST", "/web/signup", None, Some(weak), Some(ORIGIN), false)
            .await
            .status,
        StatusCode::BAD_REQUEST
    );
    let bad = json!({"email": "pas-une-adresse", "password": "une phrase de passe solide"});
    assert_eq!(
        web(&app, "POST", "/web/signup", None, Some(bad), Some(ORIGIN), false)
            .await
            .status,
        StatusCode::BAD_REQUEST
    );

    let r = web(
        &app,
        "POST",
        "/web/signup",
        None,
        Some(signup_body("Neuf@Exemple.org")),
        Some(ORIGIN),
        false,
    )
    .await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", r.json);
    assert_eq!(r.json["email"], "neuf@exemple.org");
    for flag in ["HttpOnly", "Secure", "SameSite=Strict", "Path=/"] {
        assert!(r.set_cookie.contains(flag), "{flag} absent : {}", r.set_cookie);
    }
    assert!(!r.set_cookie.contains("Domain"), "__Host- interdit Domain");
    let cookie = r.cookie.unwrap();
    assert!(
        !r.json.to_string().contains(&cookie),
        "le jeton ne doit pas apparaître dans la réponse"
    );

    // Même adresse : refusée.
    let again = web(
        &app,
        "POST",
        "/web/signup",
        None,
        Some(signup_body("neuf@exemple.org")),
        Some(ORIGIN),
        false,
    )
    .await;
    assert_eq!(again.status, StatusCode::CONFLICT);

    // Le cookie ouvre l'API en lecture…
    let me = web(&app, "GET", "/v1/me", Some(&cookie), None, None, false).await;
    assert_eq!(
        (me.status, me.json["email"].as_str()),
        (StatusCode::OK, Some("neuf@exemple.org"))
    );
    // …mais une modification exige même origine ET en-tête anti-CSRF.
    let task = json!({"text": "Écrire"});
    assert_eq!(
        web(
            &app,
            "POST",
            "/v1/tasks",
            Some(&cookie),
            Some(task.clone()),
            Some(ORIGIN),
            false
        )
        .await
        .status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        web(
            &app,
            "POST",
            "/v1/tasks",
            Some(&cookie),
            Some(task.clone()),
            Some("https://pirate.example"),
            true
        )
        .await
        .status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        web(
            &app,
            "POST",
            "/v1/tasks",
            Some(&cookie),
            Some(task.clone()),
            None,
            true
        )
        .await
        .status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        web(
            &app,
            "POST",
            "/v1/tasks",
            Some(&cookie),
            Some(task),
            Some(ORIGIN),
            true
        )
        .await
        .status,
        StatusCode::CREATED
    );

    // Un cookie ne remplace pas un jeton d'API, et inversement.
    assert_eq!(
        call(&app, "GET", "/v1/me", Some(&cookie), None).await.0,
        StatusCode::UNAUTHORIZED
    );

    // Déconnexion : cookie effacé et session révoquée.
    let out = web(
        &app,
        "POST",
        "/web/logout",
        Some(&cookie),
        None,
        Some(ORIGIN),
        true,
    )
    .await;
    assert_eq!(out.status, StatusCode::NO_CONTENT);
    assert!(out.set_cookie.contains("Max-Age=0"));
    assert_eq!(
        web(&app, "GET", "/v1/me", Some(&cookie), None, None, false)
            .await
            .status,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn web_login_password_change_and_account_deletion() {
    let Some((app, _)) = setup().await else {
        return;
    };
    let login = json!({"email": EMAIL, "password": PASSWORD});
    let a = web(
        &app,
        "POST",
        "/web/login",
        None,
        Some(login.clone()),
        Some(ORIGIN),
        false,
    )
    .await;
    assert_eq!(a.status, StatusCode::OK);
    let a = a.cookie.unwrap();
    let b = web(&app, "POST", "/web/login", None, Some(login), Some(ORIGIN), false)
        .await
        .cookie
        .unwrap();
    let (s, devices) = (
        web(&app, "GET", "/v1/devices", Some(&a), None, None, false)
            .await
            .status,
        web(&app, "GET", "/v1/devices", Some(&a), None, None, false)
            .await
            .json,
    );
    assert_eq!(s, StatusCode::OK);
    assert_eq!(devices[0]["name"], "Firefox sur Linux");
    assert_eq!(devices[0]["kind"], "web");

    // Mauvais mot de passe actuel : refusé.
    let wrong = json!({"current": "faux faux faux", "new": "nouvelle phrase de passe"});
    assert_eq!(
        web(
            &app,
            "POST",
            "/web/password",
            Some(&a),
            Some(wrong),
            Some(ORIGIN),
            true
        )
        .await
        .status,
        StatusCode::UNAUTHORIZED
    );
    let change = json!({"current": PASSWORD, "new": "nouvelle phrase de passe"});
    assert_eq!(
        web(
            &app,
            "POST",
            "/web/password",
            Some(&a),
            Some(change),
            Some(ORIGIN),
            true
        )
        .await
        .status,
        StatusCode::NO_CONTENT
    );
    // L'autre navigateur est déconnecté, celui-ci reste connecté.
    assert_eq!(
        web(&app, "GET", "/v1/me", Some(&b), None, None, false)
            .await
            .status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        web(&app, "GET", "/v1/me", Some(&a), None, None, false)
            .await
            .status,
        StatusCode::OK
    );

    let del = json!({"password": "nouvelle phrase de passe"});
    assert_eq!(
        web(
            &app,
            "POST",
            "/web/account/delete",
            Some(&a),
            Some(del),
            Some(ORIGIN),
            true
        )
        .await
        .status,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        web(&app, "GET", "/v1/me", Some(&a), None, None, false)
            .await
            .status,
        StatusCode::UNAUTHORIZED
    );
    let again = json!({"email": EMAIL, "password": "nouvelle phrase de passe"});
    assert_eq!(
        web(&app, "POST", "/web/login", None, Some(again), Some(ORIGIN), false)
            .await
            .status,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn web_totp_enrolment() {
    let Some((app, db)) = setup().await else {
        return;
    };
    let c = web(
        &app,
        "POST",
        "/web/login",
        None,
        Some(json!({"email": EMAIL, "password": PASSWORD})),
        Some(ORIGIN),
        false,
    )
    .await
    .cookie
    .unwrap();
    let setup = web(
        &app,
        "POST",
        "/web/totp/setup",
        Some(&c),
        Some(json!({"password": PASSWORD})),
        Some(ORIGIN),
        true,
    )
    .await;
    assert_eq!(setup.status, StatusCode::OK);
    assert!(setup.json["url"].as_str().unwrap().starts_with("otpauth://"));
    assert!(setup.json["qr_png"].as_str().unwrap().len() > 100);
    // Pas encore actif tant que le code n'est pas confirmé.
    let u = db::user_by_email(&db, EMAIL).await.unwrap().unwrap();
    assert!(u.totp_secret.is_none() && u.totp_pending.is_some());

    let secret = setup.json["secret"].as_str().unwrap();
    let code = totp_rs::Builder::new()
        .with_secret(totp_rs::Secret::try_from_base32(secret).unwrap())
        .with_account_name(EMAIL)
        .with_issuer(Some("Cocon"))
        .build()
        .unwrap()
        .generate(chrono::Utc::now().timestamp() as u64)
        .to_string();
    assert_eq!(
        web(
            &app,
            "POST",
            "/web/totp/confirm",
            Some(&c),
            Some(json!({"code": "000000"})),
            Some(ORIGIN),
            true
        )
        .await
        .status
            == StatusCode::NO_CONTENT,
        code == "000000"
    );
    assert_eq!(
        web(
            &app,
            "POST",
            "/web/totp/confirm",
            Some(&c),
            Some(json!({"code": code})),
            Some(ORIGIN),
            true
        )
        .await
        .status,
        StatusCode::NO_CONTENT
    );
    // Désormais, la connexion web demande le code.
    let r = web(
        &app,
        "POST",
        "/web/login",
        None,
        Some(json!({"email": EMAIL, "password": PASSWORD})),
        Some(ORIGIN),
        false,
    )
    .await;
    assert_eq!(
        (r.status, r.json["error"].as_str()),
        (StatusCode::UNAUTHORIZED, Some("totp_required"))
    );
}

#[tokio::test]
async fn signup_modes_invite_and_closed() {
    let Some(db) = Db::test().await else {
        return;
    };
    let mut st = routes::AppState::new(db.clone());
    st.signup = crate::protocol::SignupMode::Invite;
    let app = routes::router(st);
    let info = web(&app, "GET", "/web/info", None, None, None, false).await;
    assert_eq!(info.json["signup"], "invite");
    let r = web(
        &app,
        "POST",
        "/web/signup",
        None,
        Some(signup_body("a@exemple.org")),
        Some(ORIGIN),
        false,
    )
    .await;
    assert_eq!(
        (r.status, r.json["error"].as_str()),
        (StatusCode::FORBIDDEN, Some("invite_required"))
    );

    let (code, hash) = auth::new_invite_code();
    db::create_invite(&db, &hash, chrono::Utc::now() + chrono::Duration::days(1))
        .await
        .unwrap();
    let mut body = signup_body("a@exemple.org");
    body["invite"] = json!(code);
    assert_eq!(
        web(
            &app,
            "POST",
            "/web/signup",
            None,
            Some(body.clone()),
            Some(ORIGIN),
            false
        )
        .await
        .status,
        StatusCode::CREATED
    );
    // Une invitation ne sert qu'une fois.
    body["email"] = json!("b@exemple.org");
    let r = web(&app, "POST", "/web/signup", None, Some(body), Some(ORIGIN), false).await;
    assert_eq!(
        (r.status, r.json["error"].as_str()),
        (StatusCode::FORBIDDEN, Some("invalid_invite"))
    );

    let mut st = routes::AppState::new(db);
    st.signup = crate::protocol::SignupMode::Closed;
    let app = routes::router(st);
    let r = web(
        &app,
        "POST",
        "/web/signup",
        None,
        Some(signup_body("c@exemple.org")),
        Some(ORIGIN),
        false,
    )
    .await;
    assert_eq!(
        (r.status, r.json["error"].as_str()),
        (StatusCode::FORBIDDEN, Some("signup_closed"))
    );
}

#[tokio::test]
async fn forwarded_for_trusted_only_from_proxy_network() {
    let Some(db) = Db::test().await else {
        return;
    };
    // Une tentative ratée depuis `peer`, avec `forwarded` en X-Forwarded-For.
    async fn attempt(app: &Router, peer: &str, forwarded: &str) -> StatusCode {
        let body = json!({"email": "personne@exemple.org", "password": "x",
            "device_name": "Test", "device_kind": "mobile"});
        let mut req = Request::builder()
            .method("POST")
            .uri("/v1/auth/login")
            .header("x-forwarded-for", forwarded)
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        let peer: SocketAddr = format!("{peer}:40000").parse().unwrap();
        req.extensions_mut().insert(axum::extract::ConnectInfo(peer));
        app.clone().oneshot(req).await.unwrap().status()
    }

    // Proxy sur le réseau Docker : chaque client garde sa propre limite.
    let mut st = routes::AppState::new(db.clone());
    st.behind_proxy = true;
    let app = routes::router(st);
    for _ in 0..10 {
        attempt(&app, "172.18.0.5", "198.51.100.1").await;
    }
    assert_eq!(attempt(&app, "172.18.0.5", "198.51.100.1").await, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(attempt(&app, "172.18.0.5", "198.51.100.2").await, StatusCode::UNAUTHORIZED);

    // Un pair public ne choisit pas son adresse, même avec --behind-proxy.
    for i in 0..10 {
        attempt(&app, "203.0.113.7", &format!("198.51.100.{}", 10 + i)).await;
    }
    assert_eq!(attempt(&app, "203.0.113.7", "198.51.100.99").await, StatusCode::TOO_MANY_REQUESTS);

    // Sans l'option, un pair privé n'est pas un proxy de confiance.
    let app = routes::router(routes::AppState::new(db));
    for i in 0..10 {
        attempt(&app, "172.18.0.5", &format!("198.51.100.{}", 10 + i)).await;
    }
    assert_eq!(attempt(&app, "172.18.0.5", "198.51.100.99").await, StatusCode::TOO_MANY_REQUESTS);
}
