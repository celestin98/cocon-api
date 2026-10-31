//! Envoi d'e-mails en SMTP, directement auprès du serveur de messagerie
//! de l'expéditeur (aucun service tiers).
//!
//! Configuration (`.env`) :
//! - `COCON_SMTP_HOST` : serveur SMTP (par défaut `smtp.hostinger.com`) ;
//! - `COCON_SMTP_PORT` : port, 465 (TLS direct, par défaut) ou 587 (STARTTLS) ;
//! - `COCON_SMTP_TLS` : `tls` ou `starttls` (déduit du port s'il est absent) ;
//! - `COCON_SMTP_USER` : identifiant (par défaut l'adresse de l'expéditeur) ;
//! - `COCON_SMTP_PASSWORD` : mot de passe de la boîte (secret) ;
//! - `COCON_MAIL_FROM` : expéditeur (par défaut `Cocon <contact@tkcb.pro>`) ;
//! - `COCON_PUBLIC_URL` : adresse de l'interface web, citée dans le message
//!   (facultatif).

use std::time::Duration;

use anyhow::{Context, Result, bail};
use lettre::message::Mailbox;
use lettre::message::header::ContentType;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};

const DEFAULT_FROM: &str = "Cocon <contact@tkcb.pro>";
/// Messagerie Hostinger (boîte contact@tkcb.pro).
const DEFAULT_HOST: &str = "smtp.hostinger.com";
/// Durée maximale d'un envoi complet (connexion, TLS, authentification,
/// message) : bien en deçà du délai des requêtes HTTP (30 s), pour qu'un
/// serveur SMTP muet donne une erreur claire et non une requête coupée.
const SEND_TIMEOUT: Duration = Duration::from_secs(15);

pub struct Mailer {
    from: Mailbox,
    /// « smtp.hostinger.com:465 (TLS) », pour les messages d'erreur.
    server: String,
    public_url: Option<String>,
    transport: Transport,
}

enum Transport {
    Smtp(AsyncSmtpTransport<Tokio1Executor>),
    /// Tests : messages gardés en mémoire (`None` : envoi en échec).
    #[cfg(test)]
    Memory(Option<Outbox>),
}

/// Tests : messages « envoyés » (destinataire, objet, texte).
#[cfg(test)]
pub type Outbox = std::sync::Arc<std::sync::Mutex<Vec<(String, String, String)>>>;

fn env(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|v| v.trim().to_owned())
        .filter(|v| !v.is_empty())
}

impl Mailer {
    /// Lit la configuration ; erreur explicite si un réglage manque.
    pub fn from_env() -> Result<Self> {
        let from_raw = env("COCON_MAIL_FROM").unwrap_or_else(|| DEFAULT_FROM.to_owned());
        let from: Mailbox = from_raw
            .parse()
            .with_context(|| format!("COCON_MAIL_FROM invalide : {from_raw}"))?;
        let host = env("COCON_SMTP_HOST").unwrap_or_else(|| DEFAULT_HOST.to_owned());
        let password = env("COCON_SMTP_PASSWORD")
            .context("COCON_SMTP_PASSWORD manquant (variable d'environnement ou fichier .env)")?;
        let user = env("COCON_SMTP_USER").unwrap_or_else(|| from.email.to_string());
        let port: u16 = match env("COCON_SMTP_PORT") {
            Some(p) => p
                .parse()
                .with_context(|| format!("COCON_SMTP_PORT invalide : {p}"))?,
            None => 465,
        };
        let starttls = match env("COCON_SMTP_TLS").as_deref() {
            Some("tls") => false,
            Some("starttls") => true,
            Some(other) => bail!("COCON_SMTP_TLS invalide : {other} (tls ou starttls)"),
            None => port != 465,
        };
        // TLS obligatoire dans les deux cas : le mot de passe ne circule jamais en clair.
        let builder = if starttls {
            AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&host)
        } else {
            AsyncSmtpTransport::<Tokio1Executor>::relay(&host)
        }
        .with_context(|| format!("serveur SMTP invalide : {host}"))?;
        let transport = builder
            .port(port)
            .credentials(Credentials::new(user, password))
            .timeout(Some(Duration::from_secs(10)))
            .build();
        let server = format!("{host}:{port} ({})", if starttls { "STARTTLS" } else { "TLS" });
        let public_url = env("COCON_PUBLIC_URL").map(|u| u.trim_end_matches('/').to_owned());
        Ok(Self {
            from,
            server,
            public_url,
            transport: Transport::Smtp(transport),
        })
    }

    /// Tests : boîte d'envoi en mémoire.
    #[cfg(test)]
    pub fn memory() -> (Self, Outbox) {
        let outbox = Outbox::default();
        (Self::fake(Some(outbox.clone())), outbox)
    }

    /// Tests : chaque envoi échoue.
    #[cfg(test)]
    pub fn failing() -> Self {
        Self::fake(None)
    }

    #[cfg(test)]
    fn fake(outbox: Option<Outbox>) -> Self {
        Self {
            from: DEFAULT_FROM.parse().expect("expéditeur par défaut"),
            server: "mémoire".to_owned(),
            public_url: None,
            transport: Transport::Memory(outbox),
        }
    }

    async fn send(&self, to: &str, subject: &str, text: String) -> Result<()> {
        let to: Mailbox = to
            .parse()
            .with_context(|| format!("adresse e-mail invalide : {to}"))?;
        let message = Message::builder()
            .from(self.from.clone())
            .to(to.clone())
            .subject(subject)
            .header(ContentType::TEXT_PLAIN)
            .body(text.clone())?;
        match &self.transport {
            Transport::Smtp(t) => {
                let server = &self.server;
                tokio::time::timeout(SEND_TIMEOUT, t.send(message))
                    .await
                    .map_err(|_| {
                        anyhow::anyhow!(
                            "{server} ne répond pas (plus de {} s) : port sortant bloqué par \
                             l'hébergeur, ou mauvais serveur/port ?",
                            SEND_TIMEOUT.as_secs()
                        )
                    })?
                    .with_context(|| format!("échec de l'envoi par {server}"))?;
            }
            #[cfg(test)]
            Transport::Memory(outbox) => {
                let _ = message;
                let Some(outbox) = outbox else {
                    bail!("envoi en échec (test)")
                };
                outbox
                    .lock()
                    .unwrap()
                    .push((to.email.to_string(), subject.to_owned(), text));
            }
        }
        Ok(())
    }

    /// Serveur et expéditeur, pour le journal.
    pub fn describe(&self) -> String {
        format!("{} via {}", self.from, self.server)
    }

    /// Message d'essai (`cocon-api mail-test`).
    pub async fn send_test(&self, to: &str) -> Result<()> {
        self.send(
            to,
            "Test d'envoi Cocon",
            format!(
                "Ce message confirme que le serveur Cocon peut envoyer des e-mails ({}).\n",
                self.server
            ),
        )
        .await
    }

    /// Envoie le code de vérification de l'adresse (inscription).
    pub async fn send_signup_code(&self, to: &str, code: &str) -> Result<()> {
        self.send(to, &format!("Votre code Cocon : {code}"), signup_code_text(code))
            .await
    }

    /// Envoie un code d'invitation.
    pub async fn send_invite(&self, to: &str, code: &str, days: u32) -> Result<()> {
        self.send(
            to,
            "Votre invitation à Cocon",
            invite_text(self.public_url.as_deref(), code, days),
        )
        .await
    }
}

/// Texte de l'invitation. Avec l'adresse publique, un lien ouvre le
/// formulaire d'inscription, code pré-rempli (`/?invite=CODE`).
fn invite_text(public_url: Option<&str>, code: &str, days: u32) -> String {
    let how = match public_url {
        Some(url) => format!(
            "Pour créer votre compte, ouvrez ce lien (le code est déjà rempli) :\n\n    {url}/?invite={code}\n\n\
             Ou rendez-vous sur {url}, choisissez « Inscription » et saisissez ce code :"
        ),
        None => "Dans l'application Cocon, choisissez « Inscription » et saisissez ce code :".to_owned(),
    };
    format!(
        "Bonjour,\n\n\
         Vous êtes invité·e à créer un compte Cocon.\n\n\
         {how}\n\n    {code}\n\n\
         Il ne sert qu'une fois et reste valable {days} jours.\n\n\
         Si vous n'attendiez pas cette invitation, ignorez simplement ce message.\n"
    )
}

/// Texte du code de vérification de l'adresse.
fn signup_code_text(code: &str) -> String {
    format!(
        "Bonjour,\n\n\
         Voici votre code pour confirmer votre adresse et terminer votre inscription à Cocon :\n\n    {code}\n\n\
         Il est valable {minutes} minutes et ne sert qu'une fois.\n\n\
         Si vous n'avez pas demandé à créer de compte, ignorez simplement ce message : \
         sans confirmation, le compte est supprimé.\n",
        minutes = crate::auth::EMAIL_CODE_TTL.num_minutes()
    )
}

/// Contrôle minimal d'une adresse, avant de créer le code.
pub fn looks_like_email(s: &str) -> bool {
    let s = s.trim();
    s.len() <= 254
        && !s.contains(char::is_whitespace)
        && s.split_once('@').is_some_and(|(local, domain)| {
            !local.is_empty() && domain.contains('.') && !domain.starts_with('.') && !domain.ends_with('.')
        })
}

#[cfg(test)]
mod tests {
    use super::looks_like_email;

    #[test]
    fn adresses() {
        assert!(looks_like_email("ami@exemple.org"));
        assert!(looks_like_email(" ami@exemple.org "));
        for bad in [
            "",
            "ami",
            "@exemple.org",
            "ami@",
            "ami@exemple",
            "a mi@exemple.org",
            "ami@.org",
            "ami@exemple.",
        ] {
            assert!(!looks_like_email(bad), "{bad}");
        }
    }

    #[test]
    fn lien_d_invitation() {
        let t = super::invite_text(Some("https://cocon.tkcb.pro"), "ci_abc-_9", 7);
        assert!(t.contains("https://cocon.tkcb.pro/?invite=ci_abc-_9"));
        assert!(t.contains("7 jours"));
        let t = super::invite_text(None, "ci_abc", 3);
        assert!(!t.contains("?invite="));
        assert!(t.contains("ci_abc"));
    }

    #[test]
    fn expediteur_par_defaut() {
        let from: lettre::message::Mailbox = super::DEFAULT_FROM.parse().unwrap();
        assert_eq!(from.email.to_string(), "contact@tkcb.pro");
    }
}
