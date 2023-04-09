use axum::{
    body::Body,
    extract::ConnectInfo,
    http::{header::CONTENT_TYPE, method::Method, Request, StatusCode},
    middleware::{self, Next},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Router,
};
use axum_server::tls_openssl::OpenSSLConfig;
use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod, SslVerifyMode};
use openssl::x509::{
    store::{X509Store, X509StoreBuilder},
    X509,
};
use std::{net::SocketAddr, path::PathBuf};
use tower::ServiceBuilder;

use citimock::certificates::cert_manager::{KeyContent, KeyStore, SimpleKeyStore};
use citimock::handlers::authentication::authentication_v2;

#[tokio::main]
async fn main() {
    let mut ks: SimpleKeyStore = KeyStore::new("default");
    ks.store(KeyContent::new("", "", "", "", 0, 0));
    ks.get_by_client("1", "encryption_cert");

    // openssl
    let mut tls_builder = SslAcceptor::mozilla_modern_v5(SslMethod::tls()).unwrap();
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
    let trusted_client_cert_bytes = std::fs::read(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("certs")
            .join("client_cert.crt"),
    )
    .unwrap();
    let trusted_client_cert = X509::from_pem(&trusted_client_cert_bytes).unwrap();
    let mut builder = X509StoreBuilder::new().unwrap();
    let _ = builder.add_cert(trusted_client_cert);
    let store: X509Store = builder.build();

    let mut verify_mode = SslVerifyMode::empty();
    verify_mode.set(SslVerifyMode::PEER, true);
    verify_mode.set(SslVerifyMode::FAIL_IF_NO_PEER_CERT, true);
    tls_builder.set_verify_cert_store(store).unwrap();
    tls_builder.set_verify(verify_mode);
    // openssl

    let app = Router::new()
        .route("/", get(handler))
        .route("/v2/auth", post(authentication_v2))
        .layer(ServiceBuilder::new().layer(middleware::from_fn(validate_content_type)));

    let cfg = OpenSSLConfig::try_from(tls_builder).unwrap();
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    println!("listening on {}", addr);
    axum_server::bind_openssl(addr, cfg)
        .serve(app.into_make_service_with_connect_info::<SocketAddr>())
        .await
        .unwrap();
}

async fn handler(ConnectInfo(addr): ConnectInfo<SocketAddr>) -> Html<String> {
    Html(format!("<h1>Hello, world! {}", addr.to_string()))
}

async fn validate_content_type(
    request: Request<Body>,
    next: Next<Body>,
) -> Result<impl IntoResponse, Response> {
    let methods_with_body = [Method::PATCH, Method::POST, Method::PUT];
    if methods_with_body.contains(request.method()) {
        let content_type_header = request.headers().get(CONTENT_TYPE);
        let content_type = content_type_header.and_then(|value| value.to_str().ok());

        if let Some(content_type) = content_type {
            if !(content_type.starts_with("application/xml")
                || content_type.starts_with("text/xml"))
            {
                return Err(StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response());
            }
        } else {
            return Err(StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response());
        }
    }

    Ok(next.run(request).await)
}
