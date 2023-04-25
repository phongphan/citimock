// validate basic/token authentication, extract the certificates, and set the session states
use crate::services::jwt_service;
use crate::AppState;
use crate::EncryptCertPem;
use crate::SessionState;
use crate::VerifyCertPem;
use axum::body::Body;
use axum::{
    extract::{FromRequestParts, Query, TypedHeader},
    headers::authorization::{Authorization, Basic, Bearer},
    http::Request,
    response::Response,
};
use futures_util::future::BoxFuture;
use serde::Deserialize;
use sqlx::PgPool;
use std::task::{Context, Poll};
use tower::{Layer, Service};

#[derive(Clone)]
pub struct AuthenticationLayer {
    state: AppState,
}

impl AuthenticationLayer {
    pub fn new(state: AppState) -> Self {
        AuthenticationLayer { state }
    }
}

impl<S> Layer<S> for AuthenticationLayer {
    type Service = AuthenticationService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        AuthenticationService {
            inner,
            state: self.state.clone(),
        }
    }
}

#[derive(Clone)]
pub struct AuthenticationService<S> {
    inner: S,
    state: AppState,
}

#[derive(Debug, Deserialize)]
struct ClientId {
    #[serde(rename = "clientId")]
    client_id: String,
}

impl<S> Service<Request<Body>> for AuthenticationService<S>
where
    S: Service<Request<Body>, Response = Response> + Clone + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: Request<Body>) -> Self::Future {
        let mut inner = self.inner.clone();
        let state = self.state.clone();
        let (mut parts, body) = request.into_parts();
        Box::pin(async move {
            if let Ok(TypedHeader(Authorization(bearer))) =
                TypedHeader::<Authorization<Bearer>>::from_request_parts(&mut parts, &state).await
            {
                println!("token: {}", bearer.token());
                if let Ok(Query(ClientId { client_id })) =
                    Query::<ClientId>::from_request_parts(&mut parts, &state).await
                {
                    println!("clientId: {:?}", client_id);
                    let dsig_opt = state.cert_manager.find_dsig_cert(&client_id).await;
                    let enc_opt = state.cert_manager.find_enc_cert(&client_id).await;
                    match (dsig_opt, enc_opt) {
                        (Some(dsig), Some(enc)) => {
                            if let Ok((_jwt_header, jwt_payload)) =
                                jwt_service::decrypt_token(&state.jwt_pri, bearer.token())
                            {
                                if jwt_payload.subject().unwrap() == client_id {
                                    let version = jwt_payload.claim("auth_version").unwrap();
                                    parts.extensions.insert::<SessionState>(SessionState {
                                        client_id,
                                        auth_type: format!("token-v{}", version),
                                        authenticated: true,
                                        dsig_cert: VerifyCertPem(dsig),
                                        enc_cert: EncryptCertPem(enc),
                                    });
                                } else {
                                    parts.extensions.insert::<SessionState>(SessionState {
                                        client_id,
                                        auth_type: "invalid-token".to_owned(),
                                        authenticated: false,
                                        dsig_cert: VerifyCertPem(dsig),
                                        enc_cert: EncryptCertPem(enc),
                                    });
                                }
                            } else {
                                parts.extensions.insert::<SessionState>(SessionState {
                                    client_id,
                                    auth_type: "invalid-token".to_owned(),
                                    authenticated: false,
                                    dsig_cert: VerifyCertPem(dsig),
                                    enc_cert: EncryptCertPem(enc),
                                });
                            }
                        }
                        _ => {
                            // FIXME: log
                            println!("ERROR: Cert not installed for {}", client_id);
                            // FIXME: extract common
                            parts.extensions.insert::<SessionState>(SessionState {
                                client_id,
                                auth_type: "invalid-client".to_owned(),
                                authenticated: false,
                                dsig_cert: state.default_dsig_cert,
                                enc_cert: state.default_enc_cert,
                            });
                        }
                    }
                } else {
                    // FIXME: extract common
                    parts.extensions.insert::<SessionState>(SessionState {
                        client_id: "".to_owned(),
                        auth_type: "invalid-client".to_owned(),
                        authenticated: false,
                        dsig_cert: state.default_dsig_cert,
                        enc_cert: state.default_enc_cert,
                    });
                }
            } else if let Ok(TypedHeader(Authorization(basic))) =
                TypedHeader::<Authorization<Basic>>::from_request_parts(&mut parts, &state).await
            {
                println!("username: {}", basic.username());
                println!("password: {}", basic.password());

                let client_id = basic.username();
                let dsig_opt = state.cert_manager.find_dsig_cert(client_id).await;
                let enc_opt = state.cert_manager.find_enc_cert(client_id).await;
                if dsig_opt.is_none() || enc_opt.is_none() {
                    // FIXME: extract common
                    parts.extensions.insert::<SessionState>(SessionState {
                        client_id: "".to_owned(),
                        auth_type: "basic".to_owned(),
                        authenticated: false,
                        dsig_cert: state.default_dsig_cert,
                        enc_cert: state.default_enc_cert,
                    });
                }

                let dsig = dsig_opt.unwrap();
                let enc = enc_opt.unwrap();

                if verify_password(&state.pool, basic.username(), basic.password()).await {
                    parts.extensions.insert::<SessionState>(SessionState {
                        client_id: client_id.to_owned(),
                        auth_type: "basic".to_owned(),
                        authenticated: true,
                        dsig_cert: VerifyCertPem(dsig),
                        enc_cert: EncryptCertPem(enc),
                    });
                } else {
                    parts.extensions.insert::<SessionState>(SessionState {
                        client_id: client_id.to_owned(),
                        auth_type: "basic".to_owned(),
                        authenticated: false,
                        dsig_cert: VerifyCertPem(dsig),
                        enc_cert: EncryptCertPem(enc),
                    });
                }
            } else {
                // FIXME: extract common
                parts.extensions.insert::<SessionState>(SessionState {
                    client_id: "".to_owned(),
                    auth_type: "basic".to_owned(),
                    authenticated: false,
                    dsig_cert: state.default_dsig_cert,
                    enc_cert: state.default_enc_cert,
                });
            }

            let request = Request::from_parts(parts, body);
            inner.call(request).await
        })
    }
}

async fn verify_password(pool: &PgPool, client_id: &str, password: &str) -> bool {
    match crate::services::client_service::get_client_by_uid(pool, client_id).await {
        Ok(client) => libpasta::verify_password(client.hash(), password),
        Err(sqlx::Error::RowNotFound) => {
            // TODO: log
            false
        }
        Err(err) => {
            println!("{:?}", err);
            false
        }
    }
}
