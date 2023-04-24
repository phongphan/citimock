use axum::{
    extract::ConnectInfo,
    middleware::{self},
    response::Html,
    routing::{get, post},
    Router,
};
use axum_server::tls_openssl::OpenSSLConfig;
use citimock::config::create_connection_pool;
use citimock::handlers::authentication::authentication_v2;
use citimock::layers::authentication::AuthenticationLayer;
use citimock::layers::authentication_check::authentication_check_layer;
use citimock::layers::document_decryption::DecryptionLayer;
use citimock::layers::document_encryption::EncryptionLayer;
use citimock::layers::document_signature_verifier::VerifierLayer;
use citimock::layers::document_signing::SigningLayer;
use citimock::services::cert_manager_service::CertManager;
use citimock::AppState;
use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod, SslVerifyMode};
use openssl::x509::{
    store::{X509Store, X509StoreBuilder},
    X509,
};
use std::sync::Arc;
use std::{error, net::SocketAddr, path::PathBuf, ptr};
use tower::ServiceBuilder;

//type SharedState = Arc<AppState>;

#[tokio::main]
async fn main() {
    let key = citimock::certificates::utils::generate_test_key().unwrap();

    init_xmlsec();
    let tmpl = include_str!("../templates/signing.xml");
    let enc_tmpl = include_str!("../templates/encryption.xml");
    //let pk = include_str!("../certs/server_pk.key");
    let my_doc = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<oAuthToken xmlns=\"http://com.citi.citiconnect/services/types/oauthtoken/v1\">
  <grantType>client_credentials</grantType>
  <scope>/authenticationservices/v1</scope>
  <sourceApplication>CCF</sourceApplication>
</oAuthToken>";

    let signed_doc =
        citimock::layers::document_signing::sign(tmpl, &key.private_key, "testkey", my_doc);
    //println!("signed: {}", signed_doc.unwrap());
    let enc_doc = citimock::layers::document_encryption::encrypt(
        enc_tmpl,
        &key.certificate,
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
    let app_state = AppState {
        cert_manager,
        pool,
        jwt_pri: include_str!("../certs/server_pk.key").to_owned(),
        jwt_pub: include_str!("../certs/server_pub.pem").to_owned(),
        default_dsig_cert: include_str!("../certs/server_cert.crt").to_owned(),
        default_enc_cert: include_str!("../certs/server_cert.crt").to_owned(),
    };
    let shared_state = Arc::new(app_state.clone());

    // openssl
    let mut tls_builder = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
    let ssl_cert = x509_slurp(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("certs")
            .join("server_cert.crt"),
    )
    .unwrap();
    tls_builder.set_certificate(ssl_cert.as_ref()).unwrap();
    tls_builder
        .set_certificate_file(
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("certs")
                .join("server_cert.crt"),
            SslFiletype::PEM,
        )
        .unwrap();
    tls_builder
        .set_private_key_file(
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("certs")
                .join("server_pk.key"),
            SslFiletype::PEM,
        )
        .unwrap();
    tls_builder.check_private_key().unwrap();

    // client verifier
    // set options to make sure to validate the peer aka mtls
    let trusted_client_cert = x509_slurp(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("certs")
            .join("client_cert.crt"),
    )
    .unwrap();
    let mut builder = X509StoreBuilder::new().unwrap();
    let _ = builder.add_cert(trusted_client_cert);
    let store: X509Store = builder.build();

    let mut verify_mode = SslVerifyMode::empty();
    verify_mode.set(SslVerifyMode::PEER, true);
    verify_mode.set(SslVerifyMode::FAIL_IF_NO_PEER_CERT, true);
    tls_builder.set_verify_cert_store(store).unwrap();
    tls_builder.set_verify(verify_mode);
    // openssl

    let health_check_router = Router::new().route("/", get(handler));
    //.with_state(Arc::clone(&shared_state));

    let signing_response_layer = SigningLayer::new(&key.private_key, "keyname", tmpl);
    let encrypt_response_layer =
        EncryptionLayer::new(&key.certificate, "xmlenc-encrypt-certificate", enc_tmpl);
    let decrypt_request_layer = DecryptionLayer::new(&key.private_key, "xmlenc-decrypt-key");
    let verify_request_layer = VerifierLayer::new(&key.certificate, "xmlenc-verifier-certificate");

    let authentication_layer = AuthenticationLayer::new(app_state.clone());

    let authenticate_router = Router::new()
        .route(
            "/authenticationservices/v2/oauth/token",
            post(authentication_v2),
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

fn x509_slurp(path_buf: PathBuf) -> Result<X509, Box<dyn error::Error>> {
    let data = std::fs::read(path_buf)?;
    X509::from_pem(&data).map_err(|e| e.into())
}

async fn handler(ConnectInfo(addr): ConnectInfo<SocketAddr>) -> Html<String> {
    Html(format!("<h1>Hello, world! {}", addr))
}
