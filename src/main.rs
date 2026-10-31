//! `cocon-api` : serveur de l'API de Cocon, à héberger soi-même.
//!
//! Pas d'inscription publique : les comptes se créent sur le serveur, en
//! ligne de commande (`cocon-api user add`). Stockage : PostgreSQL
//! (`DATABASE_URL`, rôle dédié).

mod auth;
mod db;
mod hub;
mod hydration;
mod mail;
mod protocol;
mod routes;
mod web;
mod ws;

use std::io::{BufRead, IsTerminal, Write};
use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand, ValueEnum};

use crate::db::Db;

#[derive(Parser)]
#[command(
    name = "cocon-api",
    version,
    about = "Serveur API de Cocon (sessions en temps réel)"
)]
struct Cli {
    /// Connexion PostgreSQL, avec un rôle dédié (lue aussi dans `.env`).
    #[arg(long, env = "DATABASE_URL", global = true, hide_env_values = true)]
    database_url: Option<String>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Lance le serveur.
    Serve {
        /// Adresse d'écoute. Gardez 127.0.0.1 derrière un reverse proxy HTTPS.
        #[arg(long, env = "COCON_API_BIND", default_value = "127.0.0.1:8787")]
        bind: SocketAddr,
        /// Autorise le HTTP en clair sur une adresse publique (déconseillé :
        /// mots de passe et jetons circuleraient en clair).
        #[arg(long)]
        insecure_http: bool,
        /// Derrière un reverse proxy HTTPS sur un réseau privé (Docker,
        /// Coolify…) : écoute permise hors de 127.0.0.1, et `X-Forwarded-For`
        /// cru quand il vient d'une adresse privée.
        #[arg(long, env = "COCON_API_BEHIND_PROXY")]
        behind_proxy: bool,
        /// Inscriptions depuis l'interface web.
        #[arg(long, env = "COCON_API_SIGNUP", value_enum, default_value_t = Signup::Open)]
        signup: Signup,
    },
    /// Vérifie que le serveur local répond (healthcheck Docker/Coolify :
    /// l'image n'a ni shell ni curl). Code de sortie 0 si `/health` répond.
    Health {
        /// Adresse d'écoute du serveur à interroger.
        #[arg(long, env = "COCON_API_BIND", default_value = "127.0.0.1:8787")]
        bind: SocketAddr,
    },
    /// Envoie un e-mail d'essai pour vérifier la configuration SMTP
    /// (affiche la cause exacte en cas d'échec).
    MailTest {
        /// Adresse destinataire.
        to: String,
    },
    /// Crée un code d'invitation (inscription en mode « invite »).
    Invite {
        /// Validité en jours.
        #[arg(long, default_value_t = 7)]
        days: u32,
        /// Envoie le code à cette adresse par e-mail (SMTP : voir
        /// `COCON_SMTP_HOST`, `COCON_SMTP_PASSWORD` et `COCON_MAIL_FROM`).
        #[arg(long)]
        email: Option<String>,
    },
    /// Gestion des comptes.
    User {
        #[command(subcommand)]
        command: UserCommand,
    },
    /// Liste les appareils d'un compte.
    Devices { email: String },
    /// Révoque un appareil (déconnexion immédiate).
    Revoke { device_id: String },
    /// Affiche le journal d'audit.
    Audit {
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },
}

#[derive(Subcommand)]
enum UserCommand {
    /// Crée un compte (le mot de passe est demandé).
    Add { email: String },
    /// Change le mot de passe (déconnecte tous les appareils).
    Passwd { email: String },
    /// Active ou désactive la double authentification (TOTP).
    Totp { email: String, state: OnOff },
    /// Déverrouille un compte après trop d'échecs.
    Unlock { email: String },
    /// Supprime un compte et toutes ses données (appareils, tâches…).
    Delete { email: String },
    /// Liste les comptes.
    List,
}

#[derive(Clone, Copy, ValueEnum)]
enum Signup {
    Open,
    Invite,
    Closed,
}

impl From<Signup> for protocol::SignupMode {
    fn from(s: Signup) -> Self {
        match s {
            Signup::Open => protocol::SignupMode::Open,
            Signup::Invite => protocol::SignupMode::Invite,
            Signup::Closed => protocol::SignupMode::Closed,
        }
    }
}

#[derive(Clone, Copy, ValueEnum)]
enum OnOff {
    On,
    Off,
}

/// Lit un mot de passe sans l'afficher (ou sur l'entrée standard sans
/// terminal, pour l'automatisation).
fn read_secret(prompt: &str) -> Result<String> {
    use nix::sys::termios::{LocalFlags, SetArg, tcgetattr, tcsetattr};
    let stdin = std::io::stdin();
    let mut line = String::new();
    if stdin.is_terminal() {
        eprint!("{prompt}");
        std::io::stderr().flush()?;
        let original = tcgetattr(&stdin)?;
        let mut silent = original.clone();
        silent.local_flags.remove(LocalFlags::ECHO);
        tcsetattr(&stdin, SetArg::TCSANOW, &silent)?;
        let r = stdin.lock().read_line(&mut line);
        tcsetattr(&stdin, SetArg::TCSANOW, &original)?;
        eprintln!();
        r?;
    } else {
        stdin.lock().read_line(&mut line)?;
    }
    Ok(line.trim_end_matches(['\n', '\r']).to_owned())
}

fn new_password() -> Result<String> {
    let p = read_secret("Mot de passe (12 caractères au moins) : ")?;
    auth::check_password_policy(&p)?;
    if std::io::stdin().is_terminal() && read_secret("Confirmation : ")? != p {
        bail!("les deux saisies diffèrent");
    }
    Ok(p)
}

async fn user_or_fail(db: &Db, email: &str) -> Result<db::UserRow> {
    db::user_by_email(db, email.trim())
        .await?
        .with_context(|| format!("aucun compte {email}"))
}

async fn admin(db: &Db, command: Command) -> Result<()> {
    match command {
        Command::Serve { .. } | Command::Health { .. } | Command::MailTest { .. } => unreachable!(),
        Command::User { command } => match command {
            UserCommand::Add { email } => {
                let email = email.trim().to_lowercase();
                if !email.contains('@') || email.len() > 254 {
                    bail!("adresse e-mail invalide");
                }
                let hash = auth::hash_password(&new_password()?)?;
                let id = db::create_user(db, &email, &hash).await?;
                db::audit(db, Some(id), None, None, "user_created", &email).await;
                println!("Compte {email} créé.");
            }
            UserCommand::Passwd { email } => {
                let u = user_or_fail(db, &email).await?;
                let hash = auth::hash_password(&new_password()?)?;
                db::set_password(db, u.id, &hash).await?;
                for d in db::list_devices(db, u.id).await? {
                    db::revoke_device(db, &d.id).await?;
                }
                db::audit(
                    db,
                    Some(u.id),
                    None,
                    None,
                    "password_changed",
                    "appareils révoqués",
                )
                .await;
                println!("Mot de passe changé ; tous les appareils devront se reconnecter.");
            }
            UserCommand::Totp { email, state } => {
                let u = user_or_fail(db, &email).await?;
                match state {
                    OnOff::On => {
                        let (secret, url) = auth::new_totp(&u.email)?;
                        db::set_totp(db, u.id, Some(&secret)).await?;
                        db::audit(db, Some(u.id), None, None, "totp_enabled", "").await;
                        println!("Double authentification activée.");
                        println!("Ajoutez ce compte dans votre application d'authentification :");
                        println!("  {url}");
                        println!("(clé à saisir à la main : {secret})");
                    }
                    OnOff::Off => {
                        db::set_totp(db, u.id, None).await?;
                        db::audit(db, Some(u.id), None, None, "totp_disabled", "").await;
                        println!("Double authentification désactivée.");
                    }
                }
            }
            UserCommand::Unlock { email } => {
                let u = user_or_fail(db, &email).await?;
                db::reset_failures(db, u.id).await?;
                println!("Compte {} déverrouillé.", u.email);
            }
            UserCommand::Delete { email } => {
                let u = user_or_fail(db, &email).await?;
                db::delete_user(db, u.id).await?;
                db::audit(db, None, None, None, "user_deleted", &u.email).await;
                println!("Compte {} supprimé.", u.email);
            }
            UserCommand::List => {
                for u in db::list_users(db).await? {
                    println!(
                        "{}  TOTP : {}{}{}",
                        u.email,
                        if u.totp_secret.is_some() { "oui" } else { "non" },
                        if u.locked_until.is_some_and(|t| t > chrono::Utc::now()) {
                            "  (verrouillé)"
                        } else {
                            ""
                        },
                        if u.email_verified { "" } else { "  (adresse non confirmée)" }
                    );
                }
            }
        },
        Command::Devices { email } => {
            let u = user_or_fail(db, &email).await?;
            for d in db::list_devices(db, u.id).await? {
                println!(
                    "{}  {:<8} {:<30} vu : {}",
                    d.id,
                    format!("{:?}", d.kind),
                    d.name,
                    d.last_seen
                        .map_or("jamais".into(), |t| t.format("%Y-%m-%d %H:%M").to_string())
                );
            }
        }
        Command::Revoke { device_id } => {
            if db::revoke_device(db, &device_id).await? {
                db::audit(
                    db,
                    None,
                    Some(&device_id),
                    None,
                    "device_revoked",
                    "administration",
                )
                .await;
                println!("Appareil révoqué (déconnecté au plus tard à sa prochaine requête).");
            } else {
                println!("Appareil introuvable ou déjà révoqué.");
            }
        }
        Command::Invite { days, email } => {
            let days = days.clamp(1, 90);
            // Configuration vérifiée avant de créer le code.
            let mailer = match &email {
                Some(to) => {
                    if !mail::looks_like_email(to) {
                        bail!("adresse e-mail invalide : {to}");
                    }
                    Some(mail::Mailer::from_env()?)
                }
                None => None,
            };
            let (code, hash) = auth::new_invite_code();
            let expires = chrono::Utc::now() + chrono::Duration::days(i64::from(days));
            db::create_invite(db, &hash, expires).await?;
            db::audit(db, None, None, None, "invite_created", "").await;
            match (mailer, email) {
                (Some(mailer), Some(to)) => {
                    let to = to.trim();
                    if let Err(e) = mailer.send_invite(to, &code, days).await {
                        // Le code existe déjà : on l'affiche pour ne pas le perdre.
                        eprintln!("Échec de l'envoi : {e:#}");
                        println!("Code d'invitation (usage unique, valable {days} jours) :\n  {code}");
                        bail!("invitation créée mais non envoyée à {to}");
                    }
                    db::audit(db, None, None, None, "invite_sent", to).await;
                    println!("Invitation envoyée à {to} (usage unique, valable {days} jours).");
                }
                _ => println!("Code d'invitation (usage unique, valable {days} jours) :\n  {code}"),
            }
        }
        Command::Audit { limit } => {
            for line in db::audit_tail(db, limit.min(10_000)).await? {
                println!("{line}");
            }
        }
    }
    Ok(())
}

async fn serve(
    db: Db,
    bind: SocketAddr,
    insecure_http: bool,
    behind_proxy: bool,
    signup: Signup,
) -> Result<()> {
    if !bind.ip().is_loopback() && !insecure_http && !behind_proxy {
        bail!(
            "refus d'écouter en HTTP sur {bind} : les mots de passe et jetons circuleraient en clair.\n\
             Gardez 127.0.0.1 et placez un reverse proxy HTTPS devant (voir README), \
             ou --behind-proxy si un proxy HTTPS le joint par un réseau privé (Docker)."
        );
    }
    // Inscription libre : chaque adresse est confirmée par un code envoyé
    // par e-mail. Sans SMTP, des comptes resteraient impossibles à confirmer.
    let signup: protocol::SignupMode = signup.into();
    let mailer = if signup == protocol::SignupMode::Open {
        let m = mail::Mailer::from_env().context(
            "inscription libre (COCON_API_SIGNUP=open) : configurez l'envoi des codes par e-mail \
             (RESEND_API_KEY ou COCON_SMTP_PASSWORD, voir README), ou choisissez COCON_API_SIGNUP=invite ou closed",
        )?;
        tracing::info!("e-mails : {}", m.describe());
        Some(std::sync::Arc::new(m))
    } else {
        None
    };
    if db::list_users(&db).await?.is_empty() {
        tracing::warn!("aucun compte : créez-en un avec « cocon-api user add <e-mail> »");
    }

    // Ménage horaire : jetons expirés, vieil historique d'hydratation.
    {
        let db = db.clone();
        tokio::spawn(async move {
            let mut every = tokio::time::interval(Duration::from_secs(3600));
            loop {
                every.tick().await;
                match db::purge_tokens(&db).await {
                    Ok(n) if n > 0 => tracing::info!("{n} jeton(s) expiré(s) supprimé(s)"),
                    Ok(_) => {}
                    Err(e) => tracing::warn!("ménage des jetons : {e:#}"),
                }
                match db::purge_unverified(&db, auth::UNVERIFIED_TTL).await {
                    Ok(n) if n > 0 => tracing::info!("{n} compte(s) jamais confirmé(s) supprimé(s)"),
                    Ok(_) => {}
                    Err(e) => tracing::warn!("ménage des comptes non confirmés : {e:#}"),
                }
                if let Err(e) = db::purge_hydration_log(&db, hydration::LOG_RETENTION_DAYS).await {
                    tracing::warn!("ménage de l'historique d'hydratation : {e:#}");
                }
            }
        });
    }

    let mut state = routes::AppState::new(db);
    state.signup = signup;
    state.mailer = mailer;
    state.behind_proxy = behind_proxy;
    tracing::info!("inscriptions : {:?}", state.signup);
    hydration::spawn(state.clone());
    let app = routes::router(state);
    let listener = tokio::net::TcpListener::bind(bind)
        .await
        .with_context(|| format!("écoute sur {bind}"))?;
    tracing::info!("cocon-api à l'écoute sur http://{bind}");
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
        .with_graceful_shutdown(async {
            let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("signal SIGTERM");
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = term.recv() => {}
            }
            tracing::info!("arrêt demandé");
        })
        .await?;
    Ok(())
}

/// `GET /health` en HTTP brut sur la boucle locale, sans dépendance.
fn health(bind: SocketAddr) -> Result<()> {
    use std::io::{Read, Write};
    use std::net::{Ipv4Addr, Ipv6Addr, TcpStream};
    use std::time::Duration;

    let mut addr = bind;
    if addr.ip().is_unspecified() {
        addr.set_ip(if addr.is_ipv4() {
            Ipv4Addr::LOCALHOST.into()
        } else {
            Ipv6Addr::LOCALHOST.into()
        });
    }
    let timeout = Duration::from_secs(3);
    let mut stream =
        TcpStream::connect_timeout(&addr, timeout).with_context(|| format!("{addr} injoignable"))?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    stream.write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")?;
    let mut head = [0u8; 64];
    let n = stream.read(&mut head)?;
    let line = String::from_utf8_lossy(&head[..n]);
    if line.starts_with("HTTP/1.1 200") {
        Ok(())
    } else {
        bail!("réponse inattendue : {}", line.lines().next().unwrap_or_default())
    }
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                // Sans les avis PostgreSQL (« already exists, skipping »…).
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info,sqlx::postgres::notice=warn")),
        )
        .with_writer(std::io::stderr)
        .with_ansi(std::io::stderr().is_terminal())
        .with_target(false)
        .init();

    // Secrets dans `.env` (jamais dans la ligne de commande : visible de
    // tous dans la liste des processus).
    let _ = dotenvy::dotenv();
    // TLS des appels HTTPS (Resend) : même moteur cryptographique (ring) que
    // la base et le SMTP.
    let _ = rustls::crypto::ring::default_provider().install_default();
    let cli = Cli::parse();
    if let Command::Health { bind } = cli.command {
        return health(bind);
    }
    if let Command::MailTest { to } = &cli.command {
        let mailer = mail::Mailer::from_env()?;
        println!("Envoi d'un e-mail d'essai à {to} ({})…", mailer.describe());
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
        rt.block_on(mailer.send_test(to.trim()))?;
        println!("Envoyé : vérifiez la boîte de réception (et les indésirables).");
        return Ok(());
    }
    let Some(url) = cli.database_url else {
        bail!("DATABASE_URL manquant (variable d'environnement ou fichier .env)");
    };
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
    rt.block_on(async {
        let db = Db::connect(&url).await?;
        match cli.command {
            Command::Serve {
                bind,
                insecure_http,
                behind_proxy,
                signup,
            } => serve(db, bind, insecure_http, behind_proxy, signup).await,
            other => admin(&db, other).await,
        }
    })
}

#[cfg(test)]
mod tests;
