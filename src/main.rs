use axum::{
    extract::ConnectInfo,
    middleware::{self},
    response::Html,
    routing::{get, post},
    Router,
};
use axum_server::tls_openssl::OpenSSLConfig;
use citimock::certificates::utils::TestKey;
use citimock::config::create_connection_pool;
use citimock::handlers::authentication::{oauth_token_v2, oauth_token_v3};
use citimock::layers::authentication::AuthenticationLayer;
use citimock::layers::authentication_check::authentication_check_layer;
use citimock::layers::document_decryption::DecryptionLayer;
use citimock::layers::document_encryption::EncryptionLayer;
use citimock::layers::document_signature_verifier::VerifierLayer;
use citimock::layers::document_signing::SigningLayer;
use citimock::services::cert_manager_service::CertManager;
use citimock::AppState;
use openssl::pkey::PKey;
use openssl::ssl::{SslAcceptor, SslMethod, SslVerifyMode};
use openssl::x509::{
    store::{X509Store, X509StoreBuilder},
    X509,
};
use std::sync::Arc;
use std::{net::SocketAddr, ptr};
use tower::ServiceBuilder;

#[tokio::main]
async fn main() {
    let key = citimock::certificates::utils::generate_test_key().unwrap();
    init_development_env(&key);

    init_xmlsec();
    let tmpl = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/templates/signing.xml"
    ));
    let enc_tmpl = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/templates/encryption.xml"
    ));
    //let pk = include_str!("../certs/server_pk.key");
    let my_doc = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<oAuthToken xmlns=\"http://com.citi.citiconnect/services/types/oauthtoken/v1\">
  <grantType>client_credentials</grantType>
  <scope>/authenticationservices/v1</scope>
  <sourceApplication>CCF</sourceApplication>
</oAuthToken>";

    let client_test_key = std::env::var("TEST_CLIENT_XML_DSIG_KEY").unwrap();
    let server_test_cert = std::env::var("XML_ENC_CERT").unwrap();
    let signed_doc =
        citimock::layers::document_signing::sign(tmpl, &client_test_key, "testkey", my_doc);
    //println!("signed: {}", signed_doc.unwrap());
    let enc_doc = citimock::layers::document_encryption::encrypt(
        enc_tmpl,
        &server_test_cert,
        "testcert",
        &signed_doc.unwrap(),
    );
    println!("test encrypted doc:\n{}", enc_doc.unwrap());

    let pool = create_connection_pool("citimock").await;

    let client = citimock::models::client::Client::new(
        "a-client",
        "password",
        citimock::models::client::ClientStatus::Active,
    );
    citimock::services::client_service::add_client(&pool, &client)
        .await
        .unwrap();

    let cert_manager = CertManager::new(pool.clone());

    // openssl
    let ssl_key =
        PKey::private_key_from_pem(std::env::var("MTLS_KEY").unwrap().as_bytes()).unwrap();
    let ssl_cert = X509::from_pem(std::env::var("MTLS_CERT").unwrap().as_bytes()).unwrap();
    let mut tls_builder = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
    tls_builder.set_private_key(&ssl_key).unwrap();
    tls_builder.set_certificate(&ssl_cert).unwrap();
    tls_builder.check_private_key().unwrap();

    // client verifier
    // set options to make sure to validate the peer aka mtls
    let mut builder = X509StoreBuilder::new().unwrap();
    for trusted_cert in cert_manager.load_trusted_certs().await {
        let c = X509::from_pem(trusted_cert.as_bytes()).unwrap();
        builder.add_cert(c).unwrap();
    }
    let store: X509Store = builder.build();

    let mut verify_mode = SslVerifyMode::empty();
    verify_mode.set(SslVerifyMode::PEER, true);
    verify_mode.set(SslVerifyMode::FAIL_IF_NO_PEER_CERT, true);
    tls_builder.set_verify_cert_store(store).unwrap();
    tls_builder.set_verify(verify_mode);
    // openssl

    let app_state = AppState {
        cert_manager,
        pool,
        jwt_pri: std::env::var("JWE_KEY").unwrap(),
        jwt_pub: std::env::var("JWE_PUB").unwrap(),
        default_dsig_cert: std::env::var("MTLS_CERT").unwrap(),
        default_enc_cert: std::env::var("MTLS_CERT").unwrap(),
    };
    let shared_state = Arc::new(app_state.clone());

    let health_check_router = Router::new().route("/", get(handler));
    //.with_state(Arc::clone(&shared_state));

    let dsig_key = std::env::var("XML_DSIG_KEY").unwrap();
    let enc_key = std::env::var("XML_ENC_KEY").unwrap();
    let signing_response_layer = SigningLayer::new(&dsig_key, "keyname", tmpl);
    let encrypt_response_layer = EncryptionLayer::new(enc_tmpl);
    let decrypt_request_layer = DecryptionLayer::new(&enc_key, "xmlenc-decrypt-key");
    let verify_request_layer = VerifierLayer::new();

    let authentication_layer = AuthenticationLayer::new(app_state.clone());

    let authenticate_router = Router::new()
        .route(
            "/authenticationservices/v2/oauth/token",
            post(oauth_token_v2),
        )
        .route(
            "/authenticationservices/v3/oauth/token",
            post(oauth_token_v3),
        )
        .with_state(Arc::clone(&shared_state))
        .layer(
            ServiceBuilder::new()
                .layer(authentication_layer)
                .layer(encrypt_response_layer)
                .layer(signing_response_layer)
                .layer(middleware::from_fn(authentication_check_layer))
                .layer(decrypt_request_layer)
                .layer(verify_request_layer),
        );

    //let app = health_check_router.merge(authenticate_router);
    let api_app = authenticate_router;
    let healtz_app = health_check_router;

    let cfg = OpenSSLConfig::try_from(tls_builder).unwrap();
    let addr = SocketAddr::from(([127, 0, 0, 1], 8443));
    println!("api listening on {}", addr);
    let api_server = axum_server::bind_openssl(addr, cfg)
        .serve(api_app.into_make_service_with_connect_info::<SocketAddr>());

    let healthz_addr = SocketAddr::from(([127, 0, 0, 1], 8080));
    println!("healtz listening on {}", healthz_addr);
    let healthz_server = axum::Server::bind(&healthz_addr)
        .serve(healtz_app.into_make_service_with_connect_info::<SocketAddr>());

    let (api_server_res, healthz_server_res) =
        futures_util::future::join(api_server, healthz_server).await;
    api_server_res.unwrap();
    healthz_server_res.unwrap();
}

fn init_xmlsec() {
    unsafe {
        citimock::xmlsec::xmlInitParser();
        citimock::xmlsec::xmlSubstituteEntitiesDefault(1);

        /* Init xmlsec library */
        if citimock::xmlsec::xmlSecInit() < 0 {
            panic!("Error: xmlsec initialization failed.");
        }

        /* Init crypto library */
        if citimock::xmlsec::xmlSecOpenSSLAppInit(ptr::null_mut()) < 0 {
            panic!("Error: crypto initialization failed.");
        }

        /* Init xmlsec-crypto library */
        if citimock::xmlsec::xmlSecOpenSSLInit() < 0 {
            panic!("Error: xmlsec-crypto initialization failed.");
        }
    }
}

async fn handler(ConnectInfo(addr): ConnectInfo<SocketAddr>) -> Html<String> {
    Html(format!("<h1>Hello, world! {}", addr))
}

fn init_development_env(_key: &TestKey) {
    use std::env::set_var;

    let ssl_key = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/certs/server_pk.key"));
    let ssl_pub = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/certs/server_pub.pem"));
    let ssl_cert = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/certs/server_cert.crt"
    ));

    let dsig_key = ssl_key;
    let dsig_cert = ssl_cert;
    let enc_key = ssl_key;
    let enc_cert = ssl_cert;

    set_var("MTLS_KEY", ssl_key);
    set_var("MTLS_CERT", ssl_cert);
    set_var("JWE_KEY", ssl_key);
    set_var("JWE_PUB", ssl_pub);
    set_var("XML_DSIG_KEY", dsig_key);
    set_var("XML_DSIG_CERT", dsig_cert);
    set_var("XML_ENC_KEY", enc_key);
    set_var("XML_ENC_CERT", enc_cert);

    let client_test_key = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/certs/client_pk.key"));
    let client_test_cert = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/certs/client_cert.crt"
    ));
    set_var("TEST_CLIENT_XML_DSIG_KEY", client_test_key);
    set_var("TEST_CLIENT_XML_DSIG_CERT", client_test_cert);
    set_var("TEST_CLIENT_XML_ENC_KEY", client_test_key);
    set_var("TEST_CLIENT_XML_ENC_CERT", client_test_cert);
}
