//! Relais temps réel : connecteurs des PC (commandes, état des sessions) et
//! flux d'événements des clients. Tout est en mémoire, par compte.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde_json::Value;

use crate::protocol::{AgentAction, AgentCommand, ClientEvent, CommandOutcome, ServerMessage};
use tokio::sync::{broadcast, mpsc, oneshot};

use crate::auth::random_id;

/// Délai de réponse d'un PC à une commande.
pub const COMMAND_TIMEOUT: Duration = Duration::from_secs(20);
/// Une commande non exécutée dans ce délai est refusée par le PC.
const COMMAND_TTL: chrono::Duration = chrono::Duration::seconds(30);

#[derive(Debug, PartialEq, Eq)]
pub enum CommandError {
    /// Aucun connecteur en ligne pour ce PC.
    Offline,
    Timeout,
}

struct AgentConn {
    tx: mpsc::Sender<ServerMessage>,
    conn_id: u64,
}

struct UserHub {
    events: broadcast::Sender<ClientEvent>,
    agents: HashMap<String, AgentConn>,
    pending: HashMap<String, oneshot::Sender<CommandOutcome>>,
    status: HashMap<String, (Option<Value>, DateTime<Utc>)>,
}

impl UserHub {
    fn new() -> Self {
        Self {
            events: broadcast::channel(64).0,
            agents: HashMap::new(),
            pending: HashMap::new(),
            status: HashMap::new(),
        }
    }
}

#[derive(Default)]
pub struct Hub {
    users: Mutex<HashMap<i64, UserHub>>,
    next_conn: Mutex<u64>,
}

impl Hub {
    fn with<R>(&self, user: i64, f: impl FnOnce(&mut UserHub) -> R) -> R {
        let mut users = self.users.lock().unwrap_or_else(|e| e.into_inner());
        f(users.entry(user).or_insert_with(UserHub::new))
    }

    pub fn subscribe(&self, user: i64) -> broadcast::Receiver<ClientEvent> {
        self.with(user, |u| u.events.subscribe())
    }

    pub fn publish(&self, user: i64, ev: ClientEvent) {
        self.with(user, |u| {
            let _ = u.events.send(ev);
        });
    }

    /// Enregistre le connecteur d'un PC (remplace une connexion précédente).
    pub fn register_agent(&self, user: i64, device: &str, tx: mpsc::Sender<ServerMessage>) -> u64 {
        let conn_id = {
            let mut n = self.next_conn.lock().unwrap_or_else(|e| e.into_inner());
            *n += 1;
            *n
        };
        self.with(user, |u| {
            u.agents.insert(device.to_owned(), AgentConn { tx, conn_id });
        });
        conn_id
    }

    /// Retire le connecteur, sauf s'il a déjà été remplacé.
    pub fn unregister_agent(&self, user: i64, device: &str, conn_id: u64) {
        self.with(user, |u| {
            if u.agents.get(device).is_some_and(|a| a.conn_id == conn_id) {
                u.agents.remove(device);
            }
        });
    }

    /// Coupe le connecteur d'un appareil révoqué.
    pub fn disconnect(&self, user: i64, device: &str) {
        self.with(user, |u| {
            u.agents.remove(device);
            u.status.remove(device);
        });
    }

    pub fn is_online(&self, user: i64, device: &str) -> bool {
        self.with(user, |u| u.agents.contains_key(device))
    }

    #[cfg(test)]
    pub fn online_agents(&self, user: i64) -> Vec<String> {
        self.with(user, |u| {
            let mut v: Vec<String> = u.agents.keys().cloned().collect();
            v.sort();
            v
        })
    }

    pub fn set_status(&self, user: i64, device: &str, status: Option<Value>) {
        self.with(user, |u| {
            u.status.insert(device.to_owned(), (status, Utc::now()));
        });
    }

    pub fn status(&self, user: i64, device: &str) -> (Option<Value>, Option<DateTime<Utc>>) {
        self.with(user, |u| match u.status.get(device) {
            Some((s, at)) => (s.clone(), Some(*at)),
            None => (None, None),
        })
    }

    /// Envoie un message à tous les connecteurs du compte, sauf `except`.
    pub fn broadcast_agents(&self, user: i64, msg: &ServerMessage, except: Option<&str>) {
        self.with(user, |u| {
            for (id, a) in &u.agents {
                if Some(id.as_str()) != except {
                    let _ = a.tx.try_send(msg.clone());
                }
            }
        });
    }

    pub fn new_command(action: AgentAction) -> AgentCommand {
        AgentCommand {
            id: random_id(),
            expires_at: Utc::now() + COMMAND_TTL,
            action,
        }
    }

    /// Envoie une commande à un PC et attend son résultat.
    pub async fn command(
        &self,
        user: i64,
        device: &str,
        action: AgentAction,
    ) -> Result<CommandOutcome, CommandError> {
        let cmd = Self::new_command(action);
        let id = cmd.id.clone();
        let (tx, rx) = oneshot::channel();
        let sent = self.with(user, |u| {
            let agent = u.agents.get(device)?;
            agent.tx.try_send(ServerMessage::Command(cmd)).ok()?;
            u.pending.insert(id.clone(), tx);
            Some(())
        });
        if sent.is_none() {
            return Err(CommandError::Offline);
        }
        let r = tokio::time::timeout(COMMAND_TIMEOUT, rx).await;
        self.with(user, |u| u.pending.remove(&id));
        match r {
            Ok(Ok(outcome)) => Ok(outcome),
            Ok(Err(_)) => Err(CommandError::Offline),
            Err(_) => Err(CommandError::Timeout),
        }
    }

    /// Résultat reçu d'un connecteur.
    pub fn complete(&self, user: i64, id: &str, outcome: CommandOutcome) {
        if let Some(tx) = self.with(user, |u| u.pending.remove(id)) {
            let _ = tx.send(outcome);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn commands_round_trip_and_isolation() {
        let hub = std::sync::Arc::new(Hub::default());
        assert!(matches!(
            hub.command(1, "pc", AgentAction::Start { minutes: None }).await,
            Err(CommandError::Offline)
        ));
        let (tx, mut rx) = mpsc::channel(4);
        let conn = hub.register_agent(1, "pc", tx);
        assert!(hub.is_online(1, "pc"));
        // Un autre compte ne voit pas ce PC.
        assert!(!hub.is_online(2, "pc"));

        let h = hub.clone();
        let agent = tokio::spawn(async move {
            let ServerMessage::Command(cmd) = rx.recv().await.unwrap() else {
                panic!("commande attendue")
            };
            assert!(cmd.expires_at > Utc::now());
            h.complete(1, &cmd.id, CommandOutcome::Done);
        });
        assert_eq!(
            format!(
                "{:?}",
                hub.command(1, "pc", AgentAction::Start { minutes: Some(5) })
                    .await
            ),
            format!("{:?}", Ok::<_, CommandError>(CommandOutcome::Done))
        );
        agent.await.unwrap();

        // Une reconnexion n'est pas effacée par la fin de l'ancienne.
        let (tx2, _rx2) = mpsc::channel(4);
        hub.register_agent(1, "pc", tx2);
        hub.unregister_agent(1, "pc", conn);
        assert!(hub.is_online(1, "pc"));
        hub.disconnect(1, "pc");
        assert!(hub.online_agents(1).is_empty());
    }
}
