use sqlx::types::chrono;
use uuid::Uuid;

#[derive(sqlx::Type, Debug)]
#[sqlx(type_name = "varchar")] // only for PostgreSQL to match a type definition
#[sqlx(rename_all = "lowercase")]
pub enum ClientStatus {
    Active,
    Inactive,
    Suspended,
    Deleted,
}

#[derive(Debug, sqlx::FromRow)]
pub struct Client {
    uid: String,
    name: String,
    status: ClientStatus,
    hash: String,
    inserted_at: chrono::DateTime<chrono::Utc>,
    updated_at: chrono::DateTime<chrono::Utc>,
}

impl Client {
    pub fn new(name: &str, password: &str, status: ClientStatus) -> Client {
        let now = chrono::Utc::now();
        Client {
            uid: Uuid::new_v4().to_string(),
            name: name.to_owned(),
            status,
            hash: hash_password(password),
            inserted_at: now,
            updated_at: now,
        }
    }

    pub fn uid(&self) -> &str {
        &self.uid
    }
    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn status(&self) -> &ClientStatus {
        &self.status
    }
    pub fn hash(&self) -> &str {
        &self.hash
    }
    pub fn inserted_at(&self) -> &chrono::DateTime<chrono::Utc> {
        &self.inserted_at
    }
    pub fn updated_at(&self) -> &chrono::DateTime<chrono::Utc> {
        &self.updated_at
    }
}

pub fn hash_password(password: &str) -> String {
    let hasher = libpasta::Config::with_primitive(libpasta::primitives::Pbkdf2::new(
        650_000,
        &ring::pbkdf2::PBKDF2_HMAC_SHA256,
    ));
    hasher.hash_password(password)
}
