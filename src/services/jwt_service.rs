use josekit::{
    jwe::{JweHeader, RSA_OAEP},
    jwt::{self, JwtPayload},
    JoseError,
};
use std::collections::HashMap;
use std::time::{Duration, SystemTime};

pub fn encrypt_token(
    public_key: &str,
    client_id: &str,
    claims: &HashMap<&str, &str>,
    duration: Duration,
) -> Result<String, JoseError> {
    let mut header = JweHeader::new();
    header.set_token_type("JWT");
    header.set_content_encryption("A128CBC-HS256");

    let now = SystemTime::now();
    let expires_at = now.checked_add(duration).unwrap();
    let mut payload = JwtPayload::new();
    payload.set_subject(client_id);
    for (key, value) in claims.iter() {
        payload.set_claim(key, Some(value.to_owned().into()));
    }

    payload.set_not_before(&now);
    payload.set_expires_at(&expires_at);

    // Encrypting JWT
    let encrypter = RSA_OAEP.encrypter_from_pem(public_key)?;
    let jwt = jwt::encode_with_encrypter(&payload, &header, &encrypter)?;
    Ok(jwt)
}

pub fn decrypt_token(private_key: &str, jwt: &str) -> Result<(JwtPayload, JweHeader), JoseError> {
    let decrypter = RSA_OAEP.decrypter_from_pem(private_key)?;
    let (payload, header) = jwt::decode_with_decrypter(jwt, &decrypter)?;
    Ok((payload, header))
}
