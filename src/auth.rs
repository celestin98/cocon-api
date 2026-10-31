//! Authentification : mots de passe (Argon2id), jetons opaques, double
//! authentification TOTP, limitation des tentatives.
//!
//! - Jeton d'accès : 15 min. Jeton de renouvellement : 30 jours, à usage
//!   unique ; réutiliser un jeton déjà consommé (signe de vol) révoque
//!   l'appareil entier.
//! - Les jetons sont 256 bits aléatoires ; seule leur empreinte SHA-256 est
//!   stockée.
//! - Mêmes réponses (et même temps de calcul) pour un compte inconnu et un
//!   mauvais mot de passe : pas d'énumération des comptes.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use anyhow::{Result, anyhow};
use argon2::Argon2;
use argon2::password_hash::{PasswordHasher, PasswordVerifier, phc::PasswordHash};
use base64::Engine;
use chrono::Utc;
use sha2::{Digest, Sha256};

use crate::db::{self, Db, TokenKind};
use crate::protocol::TokenPair;

pub const ACCESS_TTL: chrono::Duration = chrono::Duration::minutes(15);
pub const REFRESH_TTL: chrono::Duration = chrono::Duration::days(30);
/// Session d'un navigateur (cookie), à redonner après une semaine.
pub const WEB_TTL: chrono::Duration = chrono::Duration::days(7);
/// Échecs consécutifs avant verrouillage du compte.
pub const MAX_FAILURES: u32 = 5;
pub const LOCK_FOR: chrono::Duration = chrono::Duration::minutes(15);
pub const MIN_PASSWORD_LEN: usize = 12;
/// Code de vérification de l'adresse (inscription) : durée, essais, renvoi.
pub const EMAIL_CODE_TTL: chrono::Duration = chrono::Duration::minutes(10);
pub const EMAIL_CODE_MAX_ATTEMPTS: i32 = 5;
pub const EMAIL_CODE_RESEND_AFTER: chrono::Duration = chrono::Duration::seconds(60);
/// Un compte jamais confirmé est supprimé après ce délai.
pub const UNVERIFIED_TTL: chrono::Duration = chrono::Duration::hours(24);

// ------------------------------------------------------------ mots de passe

/// Hachage Argon2id (sel aléatoire). Coûteux : hors des threads de tokio.
pub fn hash_password(password: &str) -> Result<String> {
    Ok(Argon2::default()
        .hash_password(password.as_bytes())
        .map_err(|e| anyhow!("hachage : {e}"))?
        .to_string())
}

pub fn verify_password(password: &str, hash: &str) -> bool {
    PasswordHash::new(hash).is_ok_and(|h| Argon2::default().verify_password(password.as_bytes(), &h).is_ok())
}

/// Empreinte factice : un compte inconnu coûte autant qu'un vrai.
pub fn dummy_hash() -> &'static str {
    static H: OnceLock<String> = OnceLock::new();
    H.get_or_init(|| hash_password("cocon-compte-inexistant").unwrap_or_default())
}

pub fn check_password_policy(password: &str) -> Result<()> {
    if password.chars().count() < MIN_PASSWORD_LEN {
        return Err(anyhow!(
            "le mot de passe doit faire au moins {MIN_PASSWORD_LEN} caractères"
        ));
    }
    Ok(())
}

// ------------------------------------------------------------ jetons

fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    rand::fill(&mut b[..]);
    b
}

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Identifiant aléatoire (appareils, commandes).
pub fn random_id() -> String {
    b64(&random_bytes::<12>())
}

pub fn token_hash(token: &str) -> String {
    let digest = Sha256::digest(token.as_bytes());
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

fn new_token(prefix: &str) -> (String, String) {
    let plain = format!("{prefix}{}", b64(&random_bytes::<32>()));
    let hash = token_hash(&plain);
    (plain, hash)
}

/// Émet une paire de jetons pour un appareil.
pub async fn issue_tokens(db: &Db, device: &str) -> Result<TokenPair> {
    let now = Utc::now();
    let (access, access_hash) = new_token("ca_");
    let (refresh, refresh_hash) = new_token("cr_");
    db::insert_token(db, &access_hash, device, TokenKind::Access, now + ACCESS_TTL).await?;
    db::insert_token(db, &refresh_hash, device, TokenKind::Refresh, now + REFRESH_TTL).await?;
    Ok(TokenPair {
        access_token: access,
        expires_in: ACCESS_TTL.num_seconds() as u64,
        refresh_token: refresh,
        device_id: device.to_owned(),
    })
}

/// Session web : jeton opaque destiné au cookie `__Host-cocon`.
pub async fn issue_web_session(db: &Db, device: &str) -> Result<String> {
    let (plain, hash) = new_token("cw_");
    db::insert_token(db, &hash, device, TokenKind::Web, Utc::now() + WEB_TTL).await?;
    Ok(plain)
}

/// Code d'invitation : (code à transmettre, empreinte stockée).
/// Code à 6 chiffres envoyé par e-mail, tiré uniformément (rejet des
/// valeurs qui biaiseraient le modulo).
pub fn new_email_code() -> String {
    const LIMIT: u32 = u32::MAX - u32::MAX % 1_000_000;
    loop {
        let n = u32::from_le_bytes(random_bytes::<4>());
        if n < LIMIT {
            return format!("{:06}", n % 1_000_000);
        }
    }
}

/// Empreinte d'un code e-mail, liée au compte (le même code pour deux
/// comptes ne donne pas la même empreinte).
pub fn email_code_hash(user: i64, code: &str) -> String {
    token_hash(&format!("email-code:{user}:{code}"))
}

/// Normalise une saisie de code : chiffres seuls (« 482 913 » → « 482913 »).
pub fn clean_email_code(input: &str) -> Option<String> {
    let digits: String = input.chars().filter(|c| !c.is_whitespace() && *c != '-').collect();
    (digits.len() == 6 && digits.bytes().all(|b| b.is_ascii_digit())).then_some(digits)
}

pub fn new_invite_code() -> (String, String) {
    new_token("ci_")
}

/// Résultat de la vérification d'un jeton d'accès.
#[derive(Debug, Clone)]
pub struct Authenticated {
    pub user_id: i64,
    pub device_id: String,
    pub kind: crate::protocol::DeviceKind,
}

pub async fn check_access(db: &Db, token: &str) -> Result<Option<Authenticated>> {
    check_token(db, token, TokenKind::Access).await
}

/// Jeton de session web (cookie).
pub async fn check_web(db: &Db, token: &str) -> Result<Option<Authenticated>> {
    check_token(db, token, TokenKind::Web).await
}

async fn check_token(db: &Db, token: &str, kind: TokenKind) -> Result<Option<Authenticated>> {
    let Some(t) = db::token(db, &token_hash(token)).await? else {
        return Ok(None);
    };
    if t.kind != kind || t.expires < Utc::now() {
        return Ok(None);
    }
    let Some(d) = db::device(db, &t.device_id).await? else {
        return Ok(None);
    };
    if d.revoked {
        return Ok(None);
    }
    Ok(Some(Authenticated {
        user_id: d.user_id,
        device_id: d.id,
        kind: d.kind,
    }))
}

#[derive(Debug)]
pub enum RefreshOutcome {
    Ok(TokenPair),
    Invalid,
    /// Jeton déjà consommé : l'appareil vient d'être révoqué.
    Reused {
        device_id: String,
        user_id: i64,
    },
}

/// Renouvellement : consomme le jeton (usage unique) et en émet de nouveaux.
pub async fn refresh(db: &Db, token: &str) -> Result<RefreshOutcome> {
    let hash = token_hash(token);
    let Some(t) = db::token(db, &hash).await? else {
        return Ok(RefreshOutcome::Invalid);
    };
    if t.kind != TokenKind::Refresh || t.expires < Utc::now() {
        return Ok(RefreshOutcome::Invalid);
    }
    let Some(d) = db::device(db, &t.device_id).await?.filter(|d| !d.revoked) else {
        return Ok(RefreshOutcome::Invalid);
    };
    if t.used || !db::consume_token(db, &hash).await? {
        db::revoke_device(db, &d.id).await?;
        return Ok(RefreshOutcome::Reused {
            device_id: d.id,
            user_id: d.user_id,
        });
    }
    Ok(RefreshOutcome::Ok(issue_tokens(db, &d.id).await?))
}

// ------------------------------------------------------------ TOTP

fn totp_for(secret_b32: &str, email: &str) -> Result<totp_rs::Totp> {
    let secret = totp_rs::Secret::try_from_base32(secret_b32).map_err(|e| anyhow!("secret TOTP : {e:?}"))?;
    totp_rs::Builder::new()
        .with_secret(secret)
        .with_account_name(email)
        .with_issuer(Some("Cocon"))
        .build()
        .map_err(|e| anyhow!("TOTP : {e:?}"))
}

/// Nouveau secret : (secret base32 à stocker, URL `otpauth://` à scanner).
pub fn new_totp(email: &str) -> Result<(String, String)> {
    let secret = totp_rs::Secret::generate().to_base32();
    let url = totp_for(&secret, email)?
        .to_url()
        .map_err(|e| anyhow!("URL TOTP : {e:?}"))?;
    Ok((secret, url))
}

/// QR code (PNG en base64) à scanner avec l'application d'authentification.
pub fn totp_qr(secret_b32: &str, email: &str) -> Result<String> {
    totp_for(secret_b32, email)?
        .to_qr_base64()
        .map_err(|e| anyhow!("QR code : {e:?}"))
}

/// Vérifie un code. Renvoie le pas de temps utilisé, qui doit être
/// strictement supérieur au dernier accepté (un code ne sert qu'une fois).
pub fn check_totp(secret_b32: &str, email: &str, code: &str, last_step: u64) -> Option<u64> {
    let code: String = code.chars().filter(|c| !c.is_whitespace()).collect();
    let totp = totp_for(secret_b32, email).ok()?;
    let now = u64::try_from(Utc::now().timestamp()).ok()?;
    totp.check(&code, now).filter(|step| *step > last_step)
}

// ------------------------------------------------------------ limitation

/// Fenêtre glissante par adresse IP, pour les points d'entrée sensibles.
pub struct RateLimiter {
    max: u32,
    window: Duration,
    hits: Mutex<HashMap<IpAddr, (u32, Instant)>>,
}

impl RateLimiter {
    pub fn new(max: u32, window: Duration) -> Self {
        Self {
            max,
            window,
            hits: Mutex::default(),
        }
    }

    /// Compte une tentative ; faux si la limite est atteinte.
    pub fn allow(&self, ip: IpAddr) -> bool {
        let mut hits = self.hits.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        if hits.len() > 10_000 {
            hits.retain(|_, (_, start)| now.duration_since(*start) < self.window);
        }
        let entry = hits.entry(ip).or_insert((0, now));
        if now.duration_since(entry.1) >= self.window {
            *entry = (0, now);
        }
        entry.0 += 1;
        entry.0 <= self.max
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passwords_and_tokens() {
        let h = hash_password("correct horse battery").unwrap();
        assert!(h.starts_with("$argon2id$"));
        assert!(verify_password("correct horse battery", &h));
        assert!(!verify_password("correct horse batterY", &h));
        assert!(!verify_password("x", "pas une empreinte"));
        assert!(check_password_policy("court").is_err());

        let (a, ah) = new_token("ca_");
        let (b, _) = new_token("ca_");
        assert_ne!(a, b);
        assert!(a.starts_with("ca_") && a.len() > 40);
        assert_eq!(ah, token_hash(&a));
        assert_eq!(ah.len(), 64);
    }

    #[test]
    fn email_codes() {
        for _ in 0..200 {
            let c = new_email_code();
            assert_eq!(c.len(), 6);
            assert!(c.bytes().all(|b| b.is_ascii_digit()));
        }
        assert_eq!(clean_email_code(" 482 913 ").as_deref(), Some("482913"));
        assert_eq!(clean_email_code("482-913").as_deref(), Some("482913"));
        for bad in ["", "12345", "1234567", "abcdef", "12345a"] {
            assert!(clean_email_code(bad).is_none(), "{bad}");
        }
        assert_ne!(email_code_hash(1, "123456"), email_code_hash(2, "123456"));
    }

    #[test]
    fn totp_codes_are_single_use() {
        let (secret, url) = new_totp("moi@exemple.org").unwrap();
        assert!(url.starts_with("otpauth://totp/"));
        let totp = totp_for(&secret, "moi@exemple.org").unwrap();
        let now = Utc::now().timestamp() as u64;
        let code = totp.generate(now).to_string();
        let step = check_totp(&secret, "moi@exemple.org", &code, 0).expect("code valide");
        assert!(
            check_totp(&secret, "moi@exemple.org", &code, step).is_none(),
            "rejeu refusé"
        );
        assert!(check_totp(&secret, "moi@exemple.org", "000000", 0).is_none() || code == "000000");
    }

    #[test]
    fn rate_limit_window() {
        let rl = RateLimiter::new(3, Duration::from_secs(60));
        let ip: IpAddr = "203.0.113.7".parse().unwrap();
        assert!(rl.allow(ip) && rl.allow(ip) && rl.allow(ip));
        assert!(!rl.allow(ip));
        assert!(rl.allow("203.0.113.8".parse().unwrap()));
    }
}
