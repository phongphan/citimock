use crate::extractors::basic_auth::ExtractBasicAuth;
use axum::{
    async_trait,
    body::{Body, Bytes},
    extract::FromRequest,
    http::Request,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct AuthenticationRequest {
    grant_type: String,
    scope: String,
    source_application: String,
}

#[derive(Debug, Serialize)]
pub struct AuthenticationResponse {
    token_type: String,
    access_token: String,
    expires_in: u32,
    scope: String,
}

#[derive(Debug, Serialize)]
pub struct AuthenticationError {
    // loginResponse
    code: String,    // statusCode
    message: String, // statusMessage
}

pub async fn authentication_v2(
    ExtractBasicAuth((user, password)): ExtractBasicAuth,
    XmlEncBody(body): XmlEncBody,
) -> Json<AuthenticationResponse> {
    println!("user: {:?}", user);
    println!("password: {:?}", password);
    println!("body: {:?}", body);
    Json(AuthenticationResponse {
        token_type: "client_credentials".to_owned(),
        access_token: "thisistoken".to_owned(),
        scope: "/authenticationservices/v1".to_owned(),
        expires_in: 1800,
    })
}

pub struct XmlEncBody(Bytes);

#[async_trait]
impl<S> FromRequest<S, Body> for XmlEncBody
where
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request(req: Request<Body>, state: &S) -> Result<Self, Self::Rejection> {
        let body = Bytes::from_request(req, state)
            .await
            .map_err(|err| err.into_response())?;

        //do_thing_with_request_body(body.clone());

        Ok(Self(body))
    }
}
