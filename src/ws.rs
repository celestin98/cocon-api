//! WebSockets : `/v1/agent` (connecteur d'un PC) et `/v1/events` (flux
//! temps réel des clients). L'authentification se fait sur la requête
//! d'ouverture (en-tête `Authorization`) ; révoquer l'appareil coupe la
//! connexion.

use std::time::Duration;

use axum::extract::State;
use axum::extract::ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade};
use axum::http::StatusCode;
use axum::response::Response;
use tokio::sync::{broadcast, mpsc};

use crate::db;
use crate::protocol::*;
use crate::routes::{self, AppState, Auth, Error};

const PING_EVERY: Duration = Duration::from_secs(30);
/// Sans aucun signe de vie de l'autre côté pendant ce délai (même pas une
/// réponse aux pings), le canal est considéré comme mort et fermé : le PC
/// n'apparaît plus « en ligne » à tort, et le client se reconnecte.
const SILENCE_LIMIT: Duration = Duration::from_secs(75);
/// Messages illisibles tolérés avant de couper la connexion.
const MAX_BAD_MESSAGES: u32 = 5;

fn json(v: &impl serde::Serialize) -> Message {
    Message::Text(serde_json::to_string(v).unwrap_or_default().into())
}

async fn close(mut socket: WebSocket, reason: &'static str) {
    let _ = socket
        .send(Message::Close(Some(CloseFrame {
            code: 1008,
            reason: reason.into(),
        })))
        .await;
}

// ------------------------------------------------------------ clients

pub async fn events(State(state): State<AppState>, Auth(a): Auth, ws: WebSocketUpgrade) -> Response {
    ws.max_message_size(16 * 1024)
        .on_upgrade(move |socket| events_loop(state, a.user_id, a.device_id, socket))
}

async fn device_valid(state: &AppState, device: &str) -> bool {
    db::device(&state.db, device)
        .await
        .is_ok_and(|d| d.is_some_and(|d| !d.revoked))
}

async fn events_loop(state: AppState, user: i64, device: String, mut socket: WebSocket) {
    let mut rx = state.hub.subscribe(user);
    // État initial : une vue par PC.
    if let Ok(pcs) = routes::desktops(&state, user).await {
        for d in &pcs {
            let ev = ClientEvent::Session(routes::session_view(&state, d));
            if socket.send(json(&ev)).await.is_err() {
                return;
            }
        }
    }
    let mut ping = tokio::time::interval(PING_EVERY);
    let mut last_seen = std::time::Instant::now();
    loop {
        tokio::select! {
            ev = rx.recv() => match ev {
                Ok(ev) => {
                    if matches!(ev, ClientEvent::DevicesChanged) && !device_valid(&state, &device).await {
                        return close(socket, "appareil révoqué").await;
                    }
                    if socket.send(json(&ev)).await.is_err() {
                        return;
                    }
                }
                // Client trop lent : il relira l'état complet en se reconnectant.
                Err(broadcast::error::RecvError::Lagged(_)) => return close(socket, "retard").await,
                Err(broadcast::error::RecvError::Closed) => return,
            },
            msg = socket.recv() => match msg {
                Some(Ok(Message::Close(_))) | None | Some(Err(_)) => return,
                // Les clients n'envoient rien sur ce canal, sauf les pongs.
                Some(Ok(_)) => last_seen = std::time::Instant::now(),
            },
            _ = ping.tick() => {
                if last_seen.elapsed() > SILENCE_LIMIT {
                    return close(socket, "silence").await;
                }
                if socket.send(Message::Ping(Vec::new().into())).await.is_err()
                    || socket.send(json(&ClientEvent::Heartbeat)).await.is_err()
                {
                    return;
                }
            }
        }
    }
}

// ------------------------------------------------------------ connecteur

pub async fn agent(
    State(state): State<AppState>,
    Auth(a): Auth,
    ws: WebSocketUpgrade,
) -> Result<Response, Error> {
    if a.kind != DeviceKind::Desktop {
        return Err(Error::new(
            StatusCode::FORBIDDEN,
            "forbidden",
            "Seul un PC peut ouvrir le canal du connecteur",
        ));
    }
    Ok(ws
        .max_message_size(MAX_BODY_BYTES)
        .on_upgrade(move |socket| agent_loop(state, a.user_id, a.device_id, socket)))
}

async fn publish_view(state: &AppState, user: i64, device: &str) {
    if let Ok(Some(d)) = db::device(&state.db, device).await {
        state
            .hub
            .publish(user, ClientEvent::Session(routes::session_view(state, &d)));
    }
}

async fn agent_loop(state: AppState, user: i64, device: String, mut socket: WebSocket) {
    let (tx, mut rx) = mpsc::channel::<ServerMessage>(32);
    let conn = state.hub.register_agent(user, &device, tx);
    tracing::info!(device, "connecteur connecté");
    publish_view(&state, user, &device).await;

    let mut ping = tokio::time::interval(PING_EVERY);
    let mut bad = 0u32;
    let mut last_seen = std::time::Instant::now();
    loop {
        tokio::select! {
            out = rx.recv() => match out {
                Some(msg) => {
                    if socket.send(json(&msg)).await.is_err() {
                        break;
                    }
                }
                // Poignée retirée : appareil révoqué ou remplacé.
                None => {
                    close(socket, "connexion fermée par le serveur").await;
                    break;
                }
            },
            msg = socket.recv() => {
                // Tout message (pong compris) prouve que le PC est vivant.
                if matches!(msg, Some(Ok(_))) {
                    last_seen = std::time::Instant::now();
                }
                match msg {
                Some(Ok(Message::Text(text))) => match serde_json::from_str::<AgentMessage>(&text) {
                    Ok(m) => {
                        let replies = handle_agent_message(&state, user, &device, m).await;
                        let mut failed = false;
                        for r in replies {
                            if socket.send(json(&r)).await.is_err() {
                                failed = true;
                                break;
                            }
                        }
                        if failed {
                            break;
                        }
                    }
                    Err(e) => {
                        bad += 1;
                        tracing::warn!(device, "message du connecteur illisible : {e}");
                        if bad >= MAX_BAD_MESSAGES {
                            close(socket, "messages invalides").await;
                            break;
                        }
                    }
                },
                Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break,
                Some(Ok(_)) => {}
                }
            },
            _ = ping.tick() => {
                if last_seen.elapsed() > SILENCE_LIMIT {
                    tracing::warn!(device, "connecteur muet : canal fermé");
                    close(socket, "silence").await;
                    break;
                }
                if socket.send(Message::Ping(Vec::new().into())).await.is_err() {
                    break;
                }
            }
        }
    }
    state.hub.unregister_agent(user, &device, conn);
    tracing::info!(device, "connecteur déconnecté");
    publish_view(&state, user, &device).await;
}

/// Traite un message du connecteur ; renvoie les messages à lui répondre.
async fn handle_agent_message(
    state: &AppState,
    user: i64,
    device: &str,
    msg: AgentMessage,
) -> Vec<ServerMessage> {
    let r = async {
        let mut out = Vec::new();
        match msg {
            AgentMessage::Status { status } => {
                state.hub.set_status(user, device, status);
                publish_view(state, user, device).await;
            }
            AgentMessage::Result { id, outcome } => state.hub.complete(user, &id, outcome),
            AgentMessage::Hello {
                config_version,
                tasks_version,
                config,
                tasks,
            } => {
                out.extend(sync_config(state, user, device, config_version, config).await?);
                out.extend(sync_tasks(state, user, device, tasks_version, tasks).await?);
            }
            AgentMessage::ConfigChanged { base_version, config } => {
                out.extend(sync_config(state, user, device, base_version, Some(config)).await?);
            }
            AgentMessage::TasksChanged { base_version, tasks } => {
                out.extend(sync_tasks(state, user, device, base_version, Some(tasks)).await?);
            }
            AgentMessage::HydrationDrink => {
                crate::hydration::drink(state, user, device).await?;
            }
        }
        Ok::<_, Error>(out)
    }
    .await;
    r.unwrap_or_else(|e| {
        tracing::warn!(device, "message du connecteur refusé : {e:?}");
        Vec::new()
    })
}

/// Synchronisation : une modification locale fondée sur la version actuelle
/// est acceptée ; sinon le serveur fait foi et renvoie sa version.
async fn sync_config(
    state: &AppState,
    user: i64,
    device: &str,
    base: u64,
    local: Option<serde_json::Value>,
) -> Result<Vec<ServerMessage>, Error> {
    let current = routes::read_config(state, user).await?;
    if let Some(config) = local
        && base == current.version
        && let Some(version) = routes::store_config(state, user, base, config, Some(device)).await?
    {
        return Ok(vec![ServerMessage::ConfigAccepted { version }]);
    }
    if current.version > 0 && current.version != base {
        let cmd = crate::hub::Hub::new_command(AgentAction::ApplyConfig {
            version: current.version,
            config: current.config,
        });
        return Ok(vec![ServerMessage::Command(cmd)]);
    }
    Ok(Vec::new())
}

async fn sync_tasks(
    state: &AppState,
    user: i64,
    device: &str,
    base: u64,
    local: Option<Vec<Task>>,
) -> Result<Vec<ServerMessage>, Error> {
    let current = routes::read_tasks(state, user).await?;
    if let Some(tasks) = local
        && base == current.version
        && let Some(version) = routes::store_tasks(state, user, base, tasks, Some(device)).await?
    {
        return Ok(vec![ServerMessage::TasksAccepted { version }]);
    }
    if current.version > 0 && current.version != base {
        let cmd = crate::hub::Hub::new_command(AgentAction::ApplyTasks {
            version: current.version,
            tasks: current.tasks,
        });
        return Ok(vec![ServerMessage::Command(cmd)]);
    }
    Ok(Vec::new())
}
