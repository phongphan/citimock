// certificates manager
use std::vec::Vec;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone)]
pub struct KeyNotFoundError;

#[derive(Debug)]
pub struct KeyContent {
    client_id: String, // client id
    key_type: String, // encryption_cert|decryption_key|sign_key|validate_cert|mtls_key|mtls_cert
    alias: String,
    content: String,
    valid_from: u64, // since epoch in seconds
    valid_to: u64, // since epoch in seconds
}

impl KeyContent {
    pub fn new(client_id: &str, key_type: &str, alias: &str, content: &str, valid_from: u64, valid_to: u64) -> KeyContent {
        KeyContent {
            client_id: client_id.to_owned(),
            key_type: key_type.to_owned(),
            alias: alias.to_owned(),
            content: content.to_owned(),
            valid_from,
            valid_to
        }
    }
    
    pub fn client_id(&self) -> &str { self.client_id.as_str() }
    pub fn key_type(&self) -> &str { self.key_type.as_str() }
    pub fn alias(&self) -> &str { self.alias.as_str() }
    pub fn content(&self) -> &str { self.content.as_str() }
    pub fn valid_from(&self) -> u64 { self.valid_from }
    pub fn valid_to(&self) -> u64 { self.valid_to }
}

#[derive(Debug)]
pub struct SimpleKeyStore {
    name: String,
    data: Vec<KeyContent>
}

pub trait KeyStore {
    fn new(name: &str) -> Self;
    fn store(&mut self, key: KeyContent);
    /*
     * Pick the first valid key/cert type for the client
     */
    fn get_by_client(&self, client_id: &str, key_type: &str) -> Result<Vec<&KeyContent>, KeyNotFoundError>;
}

impl KeyStore for SimpleKeyStore {
    
    fn new(name: &str) -> SimpleKeyStore {
        SimpleKeyStore{name: name.to_owned(), data: Vec::new()}
    }

    fn store(&mut self, key: KeyContent) {
        self.data.push(key);
    }

    fn get_by_client(&self, client_id: &str, key_type: &str) -> Result<Vec<&KeyContent>, KeyNotFoundError> {
        let start = SystemTime::now();
        let since_epoch = start.duration_since(UNIX_EPOCH).unwrap_or(Duration::MAX).as_secs();
        println!("{:?}", since_epoch);
        let result: Vec<&KeyContent> = self.data.iter()
            .filter(|k| k.client_id == client_id)
            .filter(|k| k.key_type == key_type)
            .filter(|k| k.valid_from <= since_epoch && k.valid_to >= since_epoch)
            .collect();
        if result.is_empty() {
            Err(KeyNotFoundError)
        }
        else {
            Ok(result)
        }
    }
}

fn create_cert_mngr() {}
