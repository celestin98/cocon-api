//! Stockage PostgreSQL : comptes, appareils, jetons (hachés), documents
//! (configuration, tâches) et journal d'audit.
//!
//! - Aucun secret en clair : mots de passe en Argon2id, jetons en SHA-256.
//! - Les opérations sensibles sont atomiques côté SQL (consommation d'un
//!   jeton, verrouillage du compte, version des documents) : deux requêtes
//!   simultanées ne peuvent pas réussir toutes les deux.
//! - L'API doit se connecter avec un rôle dédié, sans privilèges ailleurs
//!   (voir README), jamais avec un superutilisateur.

#[cfg(test)]
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
#[cfg(test)]
use sqlx::AssertSqlSafe;
use sqlx::postgres::{PgPool, PgPoolOptions};
use sqlx::{Executor, Row};

use crate::protocol::DeviceKind;

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS users (
    id BIGSERIAL PRIMARY KEY,
    email TEXT NOT NULL,
    pw_hash TEXT NOT NULL,
    totp_secret TEXT,
    totp_last_step BIGINT NOT NULL DEFAULT 0,
    failed INTEGER NOT NULL DEFAULT 0,
    locked_until TIMESTAMPTZ,
    created TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS users_email ON users (lower(email));
CREATE TABLE IF NOT EXISTS devices (
    id TEXT PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('desktop', 'mobile')),
    created TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen TIMESTAMPTZ,
    revoked BOOLEAN NOT NULL DEFAULT false
);
CREATE INDEX IF NOT EXISTS devices_user ON devices (user_id);
CREATE TABLE IF NOT EXISTS tokens (
    hash TEXT PRIMARY KEY,
    device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    kind TEXT NOT NULL CHECK (kind IN ('access', 'refresh')),
    expires TIMESTAMPTZ NOT NULL,
    used BOOLEAN NOT NULL DEFAULT false
);
CREATE INDEX IF NOT EXISTS tokens_device ON tokens (device_id);
CREATE TABLE IF NOT EXISTS documents (
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    version BIGINT NOT NULL,
    body TEXT NOT NULL,
    updated TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, kind)
);
-- Interface web : appareils « web », sessions par cookie, invitations,
-- inscription TOTP en deux temps.
ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_pending TEXT;
ALTER TABLE devices DROP CONSTRAINT IF EXISTS devices_kind_check;
ALTER TABLE devices ADD CONSTRAINT devices_kind_check CHECK (kind IN ('desktop', 'mobile', 'web'));
ALTER TABLE tokens DROP CONSTRAINT IF EXISTS tokens_kind_check;
ALTER TABLE tokens ADD CONSTRAINT tokens_kind_check CHECK (kind IN ('access', 'refresh', 'web'));
CREATE TABLE IF NOT EXISTS invites (
    hash TEXT PRIMARY KEY,
    created TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires TIMESTAMPTZ NOT NULL,
    used_by BIGINT REFERENCES users(id) ON DELETE SET NULL
);
-- Inscription libre : adresse confirmée par un code à 6 chiffres envoyé
-- par e-mail. Les comptes existants (créés avant) sont considérés confirmés.
ALTER TABLE users ADD COLUMN IF NOT EXISTS email_verified BOOLEAN NOT NULL DEFAULT true;
CREATE TABLE IF NOT EXISTS email_codes (
    user_id BIGINT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    hash TEXT NOT NULL,
    expires TIMESTAMPTZ NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    sends INTEGER NOT NULL DEFAULT 1,
    sent TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- Hydratation : réglages (JSON validé), horloge des rappels, verres bus.
CREATE TABLE IF NOT EXISTS hydration (
    user_id BIGINT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    settings TEXT NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT false,
    last_reminder TIMESTAMPTZ,
    last_drink TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS hydration_enabled ON hydration (user_id) WHERE enabled;
CREATE TABLE IF NOT EXISTS hydration_log (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id TEXT,
    at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS hydration_log_user_at ON hydration_log (user_id, at);
-- Prises en millilitres, identifiées par l'appareil qui les a notées
-- (synchronisation sans doublon avec le journal local du PC).
ALTER TABLE hydration_log ADD COLUMN IF NOT EXISTS ml INTEGER NOT NULL DEFAULT 250;
ALTER TABLE hydration_log ADD COLUMN IF NOT EXISTS client_id TEXT NOT NULL DEFAULT gen_random_uuid()::text;
CREATE UNIQUE INDEX IF NOT EXISTS hydration_log_client ON hydration_log (user_id, client_id);
-- Réglages choisis par l'utilisateur (les comptes existants : oui).
ALTER TABLE hydration ADD COLUMN IF NOT EXISTS configured BOOLEAN NOT NULL DEFAULT true;
ALTER TABLE hydration ALTER COLUMN configured SET DEFAULT false;
CREATE TABLE IF NOT EXISTS audit (
    id BIGSERIAL PRIMARY KEY,
    at TIMESTAMPTZ NOT NULL DEFAULT now(),
    user_id BIGINT,
    device_id TEXT,
    ip TEXT,
    event TEXT NOT NULL,
    detail TEXT
);
";

/// Schéma temporaire d'un test, supprimé à la fin.
#[cfg(test)]
struct TestSchema {
    url: String,
    name: String,
}

#[cfg(test)]
impl Drop for TestSchema {
    fn drop(&mut self) {
        let (url, name) = (self.url.clone(), self.name.clone());
        // Pas de destructeur asynchrone : petit runtime dédié.
        let _ = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            rt.block_on(async {
                let pool = PgPoolOptions::new().max_connections(1).connect(&url).await?;
                // Jamais d'attente infinie sur un verrou : au pire le schéma reste.
                pool.execute("SET lock_timeout = '10s'").await?;
                pool.execute(AssertSqlSafe(format!("DROP SCHEMA IF EXISTS {name} CASCADE")))
                    .await?;
                anyhow::Ok(())
            })
        })
        .join();
    }
}

#[derive(Clone)]
pub struct Db {
    pub pool: PgPool,
    #[cfg(test)]
    _test: Option<Arc<TestSchema>>,
}

#[derive(Debug, Clone)]
pub struct UserRow {
    pub id: i64,
    pub email: String,
    pub pw_hash: String,
    pub totp_secret: Option<String>,
    /// Secret en cours d'activation (pas encore confirmé par un code).
    pub totp_pending: Option<String>,
    pub totp_last_step: u64,
    pub locked_until: Option<DateTime<Utc>>,
    /// Faux tant que le code reçu par e-mail n'a pas été saisi.
    pub email_verified: bool,
}

/// Résultat de la saisie d'un code de vérification d'adresse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmailCodeCheck {
    /// Bon code : adresse confirmée, code supprimé.
    Verified,
    /// Mauvais code (essai compté).
    Invalid,
    /// Aucun code en cours, expiré ou trop d'essais : en demander un autre.
    Expired,
}

#[derive(Debug, Clone)]
pub struct DeviceRow {
    pub id: String,
    pub user_id: i64,
    pub name: String,
    pub kind: DeviceKind,
    pub created: DateTime<Utc>,
    pub last_seen: Option<DateTime<Utc>>,
    pub revoked: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenKind {
    Access,
    Refresh,
    /// Session d'un navigateur (cookie HttpOnly).
    Web,
}

impl TokenKind {
    fn as_str(self) -> &'static str {
        match self {
            TokenKind::Access => "access",
            TokenKind::Refresh => "refresh",
            TokenKind::Web => "web",
        }
    }
}

#[derive(Debug, Clone)]
pub struct TokenRow {
    pub device_id: String,
    pub kind: TokenKind,
    pub expires: DateTime<Utc>,
    pub used: bool,
}

fn kind_str(k: DeviceKind) -> &'static str {
    match k {
        DeviceKind::Desktop => "desktop",
        DeviceKind::Mobile => "mobile",
        DeviceKind::Web => "web",
    }
}

fn parse_kind(s: &str) -> DeviceKind {
    match s {
        "desktop" => DeviceKind::Desktop,
        "web" => DeviceKind::Web,
        _ => DeviceKind::Mobile,
    }
}

impl Db {
    /// Connexion et création du schéma (idempotente).
    pub async fn connect(url: &str) -> Result<Self> {
        let pool = PgPoolOptions::new()
            .max_connections(10)
            .acquire_timeout(std::time::Duration::from_secs(5))
            .connect(url)
            .await
            .context("connexion à PostgreSQL (vérifiez DATABASE_URL)")?;
        let db = Self {
            pool,
            #[cfg(test)]
            _test: None,
        };
        db.migrate().await?;
        Ok(db)
    }

    #[cfg(test)]
    /// Base de test : un schéma neuf dans `TEST_DATABASE_URL`, supprimé à
    /// la fin du test. `None` si la variable n'est pas définie.
    pub async fn test() -> Option<Self> {
        let _ = dotenvy::dotenv();
        let url = std::env::var("TEST_DATABASE_URL").ok()?;
        let name = format!(
            "t_{}",
            crate::auth::random_id().to_lowercase().replace(['-', '_'], "")
        );
        let setup = PgPoolOptions::new().max_connections(1).connect(&url).await.ok()?;
        // Nom produit ici, uniquement [a-z0-9] : sans risque d'injection.
        debug_assert!(name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'));
        setup
            .execute(AssertSqlSafe(format!("CREATE SCHEMA {name}")))
            .await
            .ok()?;
        let search_path = name.clone();
        let pool = PgPoolOptions::new()
            .max_connections(4)
            .after_connect(move |conn, _| {
                let sql = AssertSqlSafe(format!("SET search_path TO {search_path}"));
                Box::pin(async move {
                    conn.execute(sql).await?;
                    Ok(())
                })
            })
            .connect(&url)
            .await
            .ok()?;
        let db = Self {
            pool,
            _test: Some(Arc::new(TestSchema { url, name })),
        };
        db.migrate().await.ok()?;
        Some(db)
    }

    async fn migrate(&self) -> Result<()> {
        // Verrou consultatif : deux instances qui démarrent ensemble ne se
        // gênent pas pendant la création du schéma.
        let mut tx = self.pool.begin().await?;
        tx.execute("SELECT pg_advisory_xact_lock(727274)").await?;
        tx.execute(SCHEMA).await.context("création du schéma")?;
        tx.commit().await?;
        Ok(())
    }
}

// ------------------------------------------------------------ comptes

/// Colonnes lues (macro : les requêtes restent des littéraux, voir `concat!`).
macro_rules! user_cols {
    () => {
        "id, email, pw_hash, totp_secret, totp_pending, totp_last_step, locked_until, email_verified"
    };
}

fn user_row(r: &sqlx::postgres::PgRow) -> Result<UserRow> {
    Ok(UserRow {
        id: r.try_get("id")?,
        email: r.try_get("email")?,
        pw_hash: r.try_get("pw_hash")?,
        totp_secret: r.try_get("totp_secret")?,
        totp_pending: r.try_get("totp_pending")?,
        totp_last_step: r.try_get::<i64, _>("totp_last_step")?.max(0) as u64,
        locked_until: r.try_get("locked_until")?,
        email_verified: r.try_get("email_verified")?,
    })
}

pub async fn create_user(db: &Db, email: &str, pw_hash: &str) -> Result<i64> {
    let r =
        sqlx::query("INSERT INTO users (email, pw_hash) VALUES ($1, $2) ON CONFLICT DO NOTHING RETURNING id")
            .bind(email)
            .bind(pw_hash)
            .fetch_optional(&db.pool)
            .await?;
    match r {
        Some(row) => Ok(row.try_get("id")?),
        None => bail!("le compte {email} existe déjà"),
    }
}

/// Inscription libre : compte en attente de confirmation de l'adresse.
/// `None` si l'adresse est déjà prise.
pub async fn create_unverified_user(db: &Db, email: &str, pw_hash: &str) -> Result<Option<i64>> {
    let r = sqlx::query(
        "INSERT INTO users (email, pw_hash, email_verified) VALUES ($1, $2, false)
         ON CONFLICT DO NOTHING RETURNING id",
    )
    .bind(email)
    .bind(pw_hash)
    .fetch_optional(&db.pool)
    .await?;
    r.map(|row| row.try_get("id")).transpose().map_err(Into::into)
}

/// Enregistre un nouveau code (remplace le précédent, essais remis à zéro).
/// Faux si `max_sends` codes ont déjà été envoyés à ce compte : le nombre
/// total d'essais reste borné, même en redemandant des codes.
pub async fn set_email_code(
    db: &Db,
    user: i64,
    hash: &str,
    expires: DateTime<Utc>,
    max_sends: i32,
) -> Result<bool> {
    Ok(sqlx::query(
        "INSERT INTO email_codes (user_id, hash, expires) VALUES ($1, $2, $3)
         ON CONFLICT (user_id) DO UPDATE
            SET hash = $2, expires = $3, attempts = 0, sent = now(), sends = email_codes.sends + 1
            WHERE email_codes.sends < $4
         RETURNING sends",
    )
    .bind(user)
    .bind(hash)
    .bind(expires)
    .bind(max_sends)
    .fetch_optional(&db.pool)
    .await?
    .is_some())
}

/// Nombre de codes déjà envoyés à ce compte (0 si aucun).
pub async fn email_code_sends(db: &Db, user: i64) -> Result<i32> {
    Ok(sqlx::query("SELECT sends FROM email_codes WHERE user_id = $1")
        .bind(user)
        .fetch_optional(&db.pool)
        .await?
        .map(|r| r.try_get("sends"))
        .transpose()?
        .unwrap_or(0))
}

/// Date d'envoi du dernier code (limite les renvois).
pub async fn email_code_sent(db: &Db, user: i64) -> Result<Option<DateTime<Utc>>> {
    Ok(sqlx::query("SELECT sent FROM email_codes WHERE user_id = $1")
        .bind(user)
        .fetch_optional(&db.pool)
        .await?
        .map(|r| r.try_get("sent"))
        .transpose()?)
}

/// Vérifie un code, atomiquement (ligne verrouillée) : deux essais
/// simultanés ne dépassent pas le nombre d'essais permis.
pub async fn check_email_code(db: &Db, user: i64, hash: &str, max_attempts: i32) -> Result<EmailCodeCheck> {
    let mut tx = db.pool.begin().await?;
    let row = sqlx::query(
        "SELECT hash, expires > now() AS live, attempts FROM email_codes WHERE user_id = $1 FOR UPDATE",
    )
    .bind(user)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(row) = row else {
        tx.rollback().await?;
        return Ok(EmailCodeCheck::Expired);
    };
    let (stored, live, attempts): (String, bool, i32) = (
        row.try_get("hash")?,
        row.try_get("live")?,
        row.try_get("attempts")?,
    );
    // Ligne gardée (compteur d'envois) : seul un nouveau code la ranime.
    if !live || attempts >= max_attempts {
        tx.rollback().await?;
        return Ok(EmailCodeCheck::Expired);
    }
    if stored != hash {
        sqlx::query("UPDATE email_codes SET attempts = attempts + 1 WHERE user_id = $1")
            .bind(user)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        return Ok(EmailCodeCheck::Invalid);
    }
    sqlx::query("DELETE FROM email_codes WHERE user_id = $1")
        .bind(user)
        .execute(&mut *tx)
        .await?;
    sqlx::query("UPDATE users SET email_verified = true WHERE id = $1")
        .bind(user)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(EmailCodeCheck::Verified)
}

/// Supprime les comptes jamais confirmés, créés il y a plus de `older_than`.
pub async fn purge_unverified(db: &Db, older_than: chrono::Duration) -> Result<u64> {
    Ok(
        sqlx::query("DELETE FROM users WHERE NOT email_verified AND created < $1")
            .bind(Utc::now() - older_than)
            .execute(&db.pool)
            .await?
            .rows_affected(),
    )
}

pub async fn user_by_email(db: &Db, email: &str) -> Result<Option<UserRow>> {
    sqlx::query(concat!(
        "SELECT ",
        user_cols!(),
        " FROM users WHERE lower(email) = lower($1)"
    ))
    .bind(email)
    .fetch_optional(&db.pool)
    .await?
    .as_ref()
    .map(user_row)
    .transpose()
}

pub async fn user_by_id(db: &Db, id: i64) -> Result<Option<UserRow>> {
    sqlx::query(concat!("SELECT ", user_cols!(), " FROM users WHERE id = $1"))
        .bind(id)
        .fetch_optional(&db.pool)
        .await?
        .as_ref()
        .map(user_row)
        .transpose()
}

pub async fn list_users(db: &Db) -> Result<Vec<UserRow>> {
    sqlx::query(concat!("SELECT ", user_cols!(), " FROM users ORDER BY id"))
        .fetch_all(&db.pool)
        .await?
        .iter()
        .map(user_row)
        .collect()
}

pub async fn set_password(db: &Db, user: i64, pw_hash: &str) -> Result<()> {
    sqlx::query("UPDATE users SET pw_hash = $2, failed = 0, locked_until = NULL WHERE id = $1")
        .bind(user)
        .bind(pw_hash)
        .execute(&db.pool)
        .await?;
    Ok(())
}

pub async fn set_totp(db: &Db, user: i64, secret: Option<&str>) -> Result<()> {
    sqlx::query("UPDATE users SET totp_secret = $2, totp_last_step = 0 WHERE id = $1")
        .bind(user)
        .bind(secret)
        .execute(&db.pool)
        .await?;
    Ok(())
}

pub async fn set_totp_pending(db: &Db, user: i64, secret: Option<&str>) -> Result<()> {
    sqlx::query("UPDATE users SET totp_pending = $2 WHERE id = $1")
        .bind(user)
        .bind(secret)
        .execute(&db.pool)
        .await?;
    Ok(())
}

/// Active le secret en attente (après un code valide).
pub async fn confirm_totp(db: &Db, user: i64, step: u64) -> Result<()> {
    sqlx::query(
        "UPDATE users SET totp_secret = totp_pending, totp_pending = NULL, totp_last_step = $2
         WHERE id = $1 AND totp_pending IS NOT NULL",
    )
    .bind(user)
    .bind(step as i64)
    .execute(&db.pool)
    .await?;
    Ok(())
}

/// Supprime un compte et, en cascade, ses appareils, jetons et documents.
pub async fn delete_user(db: &Db, user: i64) -> Result<()> {
    sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user)
        .execute(&db.pool)
        .await?;
    Ok(())
}

// ------------------------------------------------------------ invitations

pub async fn create_invite(db: &Db, hash: &str, expires: DateTime<Utc>) -> Result<()> {
    sqlx::query("INSERT INTO invites (hash, expires) VALUES ($1, $2)")
        .bind(hash)
        .bind(expires)
        .execute(&db.pool)
        .await?;
    Ok(())
}

/// Inscription sur invitation : crée le compte et consomme l'invitation dans
/// une même transaction (une invitation ne sert qu'une fois).
pub async fn create_user_with_invite(
    db: &Db,
    email: &str,
    pw_hash: &str,
    invite_hash: &str,
) -> Result<Option<i64>> {
    let mut tx = db.pool.begin().await?;
    let valid = sqlx::query(
        "SELECT 1 FROM invites WHERE hash = $1 AND used_by IS NULL AND expires > now() FOR UPDATE",
    )
    .bind(invite_hash)
    .fetch_optional(&mut *tx)
    .await?
    .is_some();
    if !valid {
        // Annulation explicite : la transaction ne garde aucun verrou en suspens.
        tx.rollback().await?;
        return Ok(None);
    }
    let Some(row) =
        sqlx::query("INSERT INTO users (email, pw_hash) VALUES ($1, $2) ON CONFLICT DO NOTHING RETURNING id")
            .bind(email)
            .bind(pw_hash)
            .fetch_optional(&mut *tx)
            .await?
    else {
        tx.rollback().await?;
        bail!("le compte {email} existe déjà");
    };
    let id: i64 = row.try_get("id")?;
    sqlx::query("UPDATE invites SET used_by = $2 WHERE hash = $1")
        .bind(invite_hash)
        .bind(id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(Some(id))
}

/// Enregistre le pas TOTP utilisé ; faux si ce pas (ou un plus récent) l'a
/// déjà été : un même code rejoué, même en parallèle, n'est accepté qu'une fois.
pub async fn use_totp_step(db: &Db, user: i64, step: u64) -> Result<bool> {
    let n = sqlx::query("UPDATE users SET totp_last_step = $2 WHERE id = $1 AND totp_last_step < $2")
        .bind(user)
        .bind(step as i64)
        .execute(&db.pool)
        .await?
        .rows_affected();
    Ok(n == 1)
}

/// Échec de connexion : au `max`-ième échec consécutif, verrouille le compte.
pub async fn record_failure(db: &Db, user: i64, max: u32, lock_for: chrono::Duration) -> Result<()> {
    sqlx::query(
        "UPDATE users SET
            locked_until = CASE WHEN failed + 1 >= $2 THEN $3 ELSE locked_until END,
            failed = CASE WHEN failed + 1 >= $2 THEN 0 ELSE failed + 1 END
         WHERE id = $1",
    )
    .bind(user)
    .bind(max as i32)
    .bind(Utc::now() + lock_for)
    .execute(&db.pool)
    .await?;
    Ok(())
}

pub async fn reset_failures(db: &Db, user: i64) -> Result<()> {
    sqlx::query("UPDATE users SET failed = 0, locked_until = NULL WHERE id = $1")
        .bind(user)
        .execute(&db.pool)
        .await?;
    Ok(())
}

// ------------------------------------------------------------ appareils

macro_rules! device_cols {
    () => {
        "id, user_id, name, kind, created, last_seen, revoked"
    };
}

fn device_row(r: &sqlx::postgres::PgRow) -> Result<DeviceRow> {
    Ok(DeviceRow {
        id: r.try_get("id")?,
        user_id: r.try_get("user_id")?,
        name: r.try_get("name")?,
        kind: parse_kind(r.try_get::<&str, _>("kind")?),
        created: r.try_get("created")?,
        last_seen: r.try_get("last_seen")?,
        revoked: r.try_get("revoked")?,
    })
}

pub async fn create_device(db: &Db, id: &str, user: i64, name: &str, kind: DeviceKind) -> Result<()> {
    sqlx::query("INSERT INTO devices (id, user_id, name, kind) VALUES ($1, $2, $3, $4)")
        .bind(id)
        .bind(user)
        .bind(name)
        .bind(kind_str(kind))
        .execute(&db.pool)
        .await?;
    Ok(())
}

pub async fn device(db: &Db, id: &str) -> Result<Option<DeviceRow>> {
    sqlx::query(concat!("SELECT ", device_cols!(), " FROM devices WHERE id = $1"))
        .bind(id)
        .fetch_optional(&db.pool)
        .await?
        .as_ref()
        .map(device_row)
        .transpose()
}

/// Appareils actifs (non révoqués) d'un compte.
pub async fn list_devices(db: &Db, user: i64) -> Result<Vec<DeviceRow>> {
    sqlx::query(concat!(
        "SELECT ",
        device_cols!(),
        " FROM devices WHERE user_id = $1 AND NOT revoked ORDER BY created"
    ))
    .bind(user)
    .fetch_all(&db.pool)
    .await?
    .iter()
    .map(device_row)
    .collect()
}

/// Révoque un appareil et efface tous ses jetons (une transaction).
pub async fn revoke_device(db: &Db, id: &str) -> Result<bool> {
    let mut tx = db.pool.begin().await?;
    let n = sqlx::query("UPDATE devices SET revoked = true WHERE id = $1 AND NOT revoked")
        .bind(id)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    sqlx::query("DELETE FROM tokens WHERE device_id = $1")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(n > 0)
}

pub async fn touch_device(db: &Db, id: &str) -> Result<()> {
    // Au plus une écriture par minute et par appareil.
    sqlx::query(
        "UPDATE devices SET last_seen = now()
         WHERE id = $1 AND (last_seen IS NULL OR last_seen < now() - interval '1 minute')",
    )
    .bind(id)
    .execute(&db.pool)
    .await?;
    Ok(())
}

// ------------------------------------------------------------ jetons

pub async fn insert_token(
    db: &Db,
    hash: &str,
    device: &str,
    kind: TokenKind,
    expires: DateTime<Utc>,
) -> Result<()> {
    sqlx::query("INSERT INTO tokens (hash, device_id, kind, expires) VALUES ($1, $2, $3, $4)")
        .bind(hash)
        .bind(device)
        .bind(kind.as_str())
        .bind(expires)
        .execute(&db.pool)
        .await?;
    Ok(())
}

pub async fn token(db: &Db, hash: &str) -> Result<Option<TokenRow>> {
    let Some(r) = sqlx::query("SELECT device_id, kind, expires, used FROM tokens WHERE hash = $1")
        .bind(hash)
        .fetch_optional(&db.pool)
        .await?
    else {
        return Ok(None);
    };
    Ok(Some(TokenRow {
        device_id: r.try_get("device_id")?,
        kind: match r.try_get::<&str, _>("kind")? {
            "refresh" => TokenKind::Refresh,
            "web" => TokenKind::Web,
            _ => TokenKind::Access,
        },
        expires: r.try_get("expires")?,
        used: r.try_get("used")?,
    }))
}

/// Consomme un jeton de renouvellement. Faux s'il l'était déjà : entre deux
/// requêtes simultanées, une seule gagne.
pub async fn consume_token(db: &Db, hash: &str) -> Result<bool> {
    let n = sqlx::query("UPDATE tokens SET used = true WHERE hash = $1 AND NOT used")
        .bind(hash)
        .execute(&db.pool)
        .await?
        .rows_affected();
    Ok(n == 1)
}

/// Supprime les jetons expirés (les jetons consommés restent jusqu'à leur
/// expiration : ils servent à détecter un rejeu).
pub async fn purge_tokens(db: &Db) -> Result<u64> {
    Ok(sqlx::query("DELETE FROM tokens WHERE expires < now()")
        .execute(&db.pool)
        .await?
        .rows_affected())
}

// ------------------------------------------------------------ documents

pub async fn document(db: &Db, user: i64, kind: &str) -> Result<Option<(u64, String)>> {
    let r = sqlx::query("SELECT version, body FROM documents WHERE user_id = $1 AND kind = $2")
        .bind(user)
        .bind(kind)
        .fetch_optional(&db.pool)
        .await?;
    r.map(|r| Ok((r.try_get::<i64, _>("version")?.max(0) as u64, r.try_get("body")?)))
        .transpose()
}

/// Écrit la version `expected + 1` si la version stockée vaut `expected`
/// (0 : absent), en une seule instruction. `None` : conflit.
pub async fn put_document(db: &Db, user: i64, kind: &str, expected: u64, body: &str) -> Result<Option<u64>> {
    let row = if expected == 0 {
        sqlx::query(
            "INSERT INTO documents (user_id, kind, version, body) VALUES ($1, $2, 1, $3)
             ON CONFLICT DO NOTHING RETURNING version",
        )
        .bind(user)
        .bind(kind)
        .bind(body)
        .fetch_optional(&db.pool)
        .await?
    } else {
        sqlx::query(
            "UPDATE documents SET version = version + 1, body = $4, updated = now()
             WHERE user_id = $1 AND kind = $2 AND version = $3 RETURNING version",
        )
        .bind(user)
        .bind(kind)
        .bind(expected as i64)
        .bind(body)
        .fetch_optional(&db.pool)
        .await?
    };
    row.map(|r| Ok(r.try_get::<i64, _>("version")? as u64))
        .transpose()
}

// ------------------------------------------------------------ hydratation

#[derive(Debug, Clone)]
pub struct HydrationRow {
    pub user_id: i64,
    pub settings: String,
    pub last_reminder: Option<DateTime<Utc>>,
    pub last_drink: Option<DateTime<Utc>>,
    pub configured: bool,
}

fn hydration_row(r: &sqlx::postgres::PgRow) -> Result<HydrationRow> {
    Ok(HydrationRow {
        user_id: r.try_get("user_id")?,
        settings: r.try_get("settings")?,
        last_reminder: r.try_get("last_reminder")?,
        last_drink: r.try_get("last_drink")?,
        configured: r.try_get("configured")?,
    })
}

pub async fn hydration(db: &Db, user: i64) -> Result<Option<HydrationRow>> {
    sqlx::query(
        "SELECT user_id, settings, last_reminder, last_drink, configured FROM hydration WHERE user_id = $1",
    )
    .bind(user)
    .fetch_optional(&db.pool)
    .await?
    .map(|r| hydration_row(&r))
    .transpose()
}

/// Enregistre les réglages ; l'horloge des rappels repart de maintenant.
pub async fn put_hydration(db: &Db, user: i64, settings: &str, enabled: bool) -> Result<()> {
    sqlx::query(
        "INSERT INTO hydration (user_id, settings, enabled, last_reminder, configured)
         VALUES ($1, $2, $3, now(), true)
         ON CONFLICT (user_id) DO UPDATE SET settings = $2, enabled = $3, last_reminder = now(), configured = true",
    )
    .bind(user)
    .bind(settings)
    .bind(enabled)
    .execute(&db.pool)
    .await?;
    Ok(())
}

pub async fn hydration_enabled(db: &Db) -> Result<Vec<HydrationRow>> {
    sqlx::query(
        "SELECT user_id, settings, last_reminder, last_drink, configured FROM hydration WHERE enabled",
    )
    .fetch_all(&db.pool)
    .await?
    .iter()
    .map(hydration_row)
    .collect()
}

/// Réserve un rappel : réussit seulement si personne ne l'a envoyé entre-temps.
pub async fn claim_reminder(
    db: &Db,
    user: i64,
    previous: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
) -> Result<bool> {
    Ok(sqlx::query(
        "UPDATE hydration SET last_reminder = $3
         WHERE user_id = $1 AND enabled AND last_reminder IS NOT DISTINCT FROM $2",
    )
    .bind(user)
    .bind(previous)
    .bind(now)
    .execute(&db.pool)
    .await?
    .rows_affected()
        == 1)
}

/// Ajoute une prise si la limite de son jour (qui commence à `day`) n'est
/// pas atteinte et si son identifiant est nouveau, en une seule
/// instruction. `defaults` : réglages si le compte n'en a pas.
pub async fn add_drink(
    db: &Db,
    user: i64,
    device: &str,
    drink: &crate::protocol::Drink,
    day: DateTime<Utc>,
    max: u32,
    defaults: &str,
) -> Result<bool> {
    let row = sqlx::query(
        "WITH ins AS (
             INSERT INTO hydration_log (user_id, device_id, client_id, at, ml)
             SELECT $1, $2, $3, $4, $5
             WHERE (SELECT count(*) FROM hydration_log
                    WHERE user_id = $1 AND at >= $6 AND at < $6 + interval '1 day') < $7
             ON CONFLICT (user_id, client_id) DO NOTHING
             RETURNING at
         )
         INSERT INTO hydration (user_id, settings, last_drink)
         SELECT $1, $8, at FROM ins
         ON CONFLICT (user_id) DO UPDATE
             SET last_drink = GREATEST(hydration.last_drink, EXCLUDED.last_drink)
         RETURNING user_id",
    )
    .bind(user)
    .bind(device)
    .bind(&drink.id)
    .bind(drink.at)
    .bind(drink.ml as i32)
    .bind(day)
    .bind(i64::from(max))
    .bind(defaults)
    .fetch_optional(&db.pool)
    .await?;
    Ok(row.is_some())
}

async fn refresh_last_drink(db: &Db, user: i64) -> Result<()> {
    sqlx::query(
        "UPDATE hydration SET last_drink = (SELECT max(at) FROM hydration_log WHERE user_id = $1)
         WHERE user_id = $1",
    )
    .bind(user)
    .execute(&db.pool)
    .await?;
    Ok(())
}

/// Retire des prises par identifiant ; renvoie le nombre retiré.
pub async fn remove_drinks(db: &Db, user: i64, ids: &[String]) -> Result<u64> {
    let n = sqlx::query("DELETE FROM hydration_log WHERE user_id = $1 AND client_id = ANY($2)")
        .bind(user)
        .bind(ids)
        .execute(&db.pool)
        .await?
        .rows_affected();
    if n > 0 {
        refresh_last_drink(db, user).await?;
    }
    Ok(n)
}

/// Prises depuis `since`, dans l'ordre.
pub async fn drinks_after(db: &Db, user: i64, since: DateTime<Utc>) -> Result<Vec<crate::protocol::Drink>> {
    sqlx::query("SELECT client_id, at, ml FROM hydration_log WHERE user_id = $1 AND at >= $2 ORDER BY at, id")
        .bind(user)
        .bind(since)
        .fetch_all(&db.pool)
        .await?
        .iter()
        .map(|r| {
            Ok(crate::protocol::Drink {
                id: r.try_get("client_id")?,
                at: r.try_get("at")?,
                ml: u32::try_from(r.try_get::<i32, _>("ml")?).unwrap_or(0),
            })
        })
        .collect()
}

/// Retire le dernier verre depuis `since`.
pub async fn undo_drink(db: &Db, user: i64, since: DateTime<Utc>) -> Result<()> {
    sqlx::query(
        "DELETE FROM hydration_log WHERE id = (
             SELECT id FROM hydration_log WHERE user_id = $1 AND at >= $2 ORDER BY at DESC, id DESC LIMIT 1
         )",
    )
    .bind(user)
    .bind(since)
    .execute(&db.pool)
    .await?;
    refresh_last_drink(db, user).await
}

/// Nombre de prises et quantité (ml) depuis `since`.
pub async fn drinks_since(db: &Db, user: i64, since: DateTime<Utc>) -> Result<(u32, u32)> {
    let r = sqlx::query(
        "SELECT count(*) AS n, COALESCE(sum(ml), 0)::BIGINT AS ml
         FROM hydration_log WHERE user_id = $1 AND at >= $2",
    )
    .bind(user)
    .bind(since)
    .fetch_one(&db.pool)
    .await?;
    let n: i64 = r.try_get("n")?;
    let ml: i64 = r.try_get("ml")?;
    Ok((
        u32::try_from(n).unwrap_or(u32::MAX),
        u32::try_from(ml).unwrap_or(u32::MAX),
    ))
}

/// Supprime l'historique plus ancien que `days` jours.
pub async fn purge_hydration_log(db: &Db, days: i64) -> Result<u64> {
    Ok(
        sqlx::query("DELETE FROM hydration_log WHERE at < now() - make_interval(days => $1::int)")
            .bind(days as i32)
            .execute(&db.pool)
            .await?
            .rows_affected(),
    )
}

// ------------------------------------------------------------ audit

pub async fn audit(
    db: &Db,
    user: Option<i64>,
    device: Option<&str>,
    ip: Option<&str>,
    event: &str,
    detail: &str,
) {
    tracing::info!(event, detail, ip, "audit");
    let r =
        sqlx::query("INSERT INTO audit (user_id, device_id, ip, event, detail) VALUES ($1, $2, $3, $4, $5)")
            .bind(user)
            .bind(device)
            .bind(ip)
            .bind(event)
            .bind(detail)
            .execute(&db.pool)
            .await;
    if let Err(e) = r {
        tracing::error!("journal d'audit : {e}");
    }
}

pub async fn audit_tail(db: &Db, limit: usize) -> Result<Vec<String>> {
    let rows = sqlx::query(
        "SELECT at, COALESCE(ip, '-') AS ip, event, COALESCE(device_id, '-') AS device,
                COALESCE(detail, '') AS detail
         FROM audit ORDER BY id DESC LIMIT $1",
    )
    .bind(limit as i64)
    .fetch_all(&db.pool)
    .await?;
    rows.iter()
        .map(|r| {
            Ok(format!(
                "{}  {:<15} {:<22} {} {}",
                r.try_get::<DateTime<Utc>, _>("at")?.format("%Y-%m-%d %H:%M:%S"),
                r.try_get::<&str, _>("ip")?,
                r.try_get::<&str, _>("event")?,
                r.try_get::<&str, _>("device")?,
                r.try_get::<&str, _>("detail")?
            ))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn documents_are_versioned_atomically() {
        let Some(db) = Db::test().await else {
            eprintln!("TEST_DATABASE_URL absent : test ignoré");
            return;
        };
        let u = create_user(&db, "moi@exemple.org", "h").await.unwrap();
        assert!(
            create_user(&db, "MOI@exemple.org", "h").await.is_err(),
            "e-mail insensible à la casse"
        );
        assert_eq!(put_document(&db, u, "config", 0, "{}").await.unwrap(), Some(1));
        assert_eq!(
            put_document(&db, u, "config", 0, "{}").await.unwrap(),
            None,
            "conflit"
        );
        // Deux écritures concurrentes sur la même version : une seule gagne.
        let (a, b) = tokio::join!(
            put_document(&db, u, "config", 1, "{\"a\":1}"),
            put_document(&db, u, "config", 1, "{\"b\":1}")
        );
        let wins = [a.unwrap(), b.unwrap()].iter().filter(|r| r.is_some()).count();
        assert_eq!(wins, 1);
        assert_eq!(document(&db, u, "config").await.unwrap().unwrap().0, 2);
    }

    #[tokio::test]
    async fn lockout_and_single_use_tokens() {
        let Some(db) = Db::test().await else {
            return;
        };
        let u = create_user(&db, "a@b.c", "h").await.unwrap();
        for _ in 0..4 {
            record_failure(&db, u, 5, chrono::Duration::minutes(15))
                .await
                .unwrap();
        }
        assert!(user_by_id(&db, u).await.unwrap().unwrap().locked_until.is_none());
        record_failure(&db, u, 5, chrono::Duration::minutes(15))
            .await
            .unwrap();
        assert!(user_by_id(&db, u).await.unwrap().unwrap().locked_until.is_some());

        create_device(&db, "d1", u, "PC", DeviceKind::Desktop)
            .await
            .unwrap();
        insert_token(
            &db,
            "h1",
            "d1",
            TokenKind::Refresh,
            Utc::now() + chrono::Duration::days(1),
        )
        .await
        .unwrap();
        let (a, b) = tokio::join!(consume_token(&db, "h1"), consume_token(&db, "h1"));
        assert!(a.unwrap() ^ b.unwrap(), "un seul usage, même en parallèle");
        assert!(revoke_device(&db, "d1").await.unwrap());
        assert!(token(&db, "h1").await.unwrap().is_none());
        assert!(list_devices(&db, u).await.unwrap().is_empty());
        assert!(use_totp_step(&db, u, 10).await.unwrap());
        assert!(!use_totp_step(&db, u, 10).await.unwrap());
    }
}
