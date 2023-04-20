use openssl::asn1::Asn1Time;
use openssl::bn::{BigNum, MsbOption};
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use openssl::x509::{X509Builder, X509Name, X509NameBuilder, X509};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(Debug)]
pub struct TestKey {
    pub private_key: String,
    pub public_key: String,
    pub certificate: String,
}

fn generate_serial_number() -> Result<BigNum> {
    let mut big: BigNum = BigNum::new_secure().unwrap();
    big.rand(128, MsbOption::MAYBE_ZERO, false)?;

    Ok(big)
}

fn generate_x509_name() -> Result<X509Name> {
    let mut x509_name = X509NameBuilder::new()?;
    x509_name.append_entry_by_text("C", "US")?;
    x509_name.append_entry_by_text("ST", "CA")?;
    x509_name.append_entry_by_text("O", "Acme Co")?;
    x509_name.append_entry_by_text("CN", "acme.example.net")?;

    Ok(x509_name.build())
}

fn generate_certificate(pkey: &PKey<Private>) -> Result<X509> {
    let mut x509_builder = X509Builder::new()?;
    x509_builder.set_serial_number(generate_serial_number()?.to_asn1_integer()?.as_ref())?;
    x509_builder.set_subject_name(generate_x509_name()?.as_ref())?;
    x509_builder.set_not_before(Asn1Time::days_from_now(0)?.as_ref())?;
    x509_builder.set_not_after(Asn1Time::days_from_now(90)?.as_ref())?;
    x509_builder.set_pubkey(pkey)?;
    x509_builder.sign(pkey, MessageDigest::sha256())?;

    Ok(x509_builder.build())
}

pub fn generate_test_key() -> Result<TestKey> {
    let pkey = PKey::from_rsa(Rsa::generate(2048)?)?;
    let cert = generate_certificate(&pkey)?;

    let private_key = pkey.private_key_to_pem_pkcs8()?;
    let public_key = pkey.public_key_to_pem()?;
    let certificate = cert.to_pem()?;

    Ok(TestKey {
        private_key: String::from_utf8(private_key)?,
        public_key: String::from_utf8(public_key)?,
        certificate: String::from_utf8(certificate)?,
    })
}
