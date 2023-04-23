// validate basic/token authentication, extract the certificates, and set the session states
use crate::extractors::error_response;
use crate::AppState;
use axum::body::Body;
use axum::{
    extract::{FromRequestParts, Query, TypedHeader},
    headers::authorization::{Authorization, Basic, Bearer},
    http::{Request, StatusCode},
    response::Response,
};
use futures_util::future::BoxFuture;
use serde::Deserialize;
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
                    parts.extensions.insert(client_id);
                } else {
                    return Ok(error_response(
                        StatusCode::UNAUTHORIZED,
                        "UNAUTHORIZED",
                        "unauthorized",
                    ));
                }
            } else if let Ok(TypedHeader(Authorization(basic))) =
                TypedHeader::<Authorization<Basic>>::from_request_parts(&mut parts, &state).await
            {
                println!("username: {}", basic.username());
                println!("password: {}", basic.password());

                parts
                    .extensions
                    .insert::<String>(basic.username().to_owned());
            } else {
                return Ok(error_response(
                    StatusCode::UNAUTHORIZED,
                    "UNAUTHORIZED",
                    "unauthorized",
                ));
            }

            let request = Request::from_parts(parts, body);
            inner.call(request).await
        })
    }
}
