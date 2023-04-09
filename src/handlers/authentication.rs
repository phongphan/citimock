use axum::{
    async_trait,
    body::{Body, Bytes},
    extract::FromRequest,
    http::Request,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};

#[derive(Serialize)]
pub struct AuthenticationResponse {
    email: String,
    password: String,
}

#[derive(Deserialize)]
pub struct AuthenticationRequest {
    email: String,
    password: String,
}

pub async fn authentication_v2(XmlEncBody(body): XmlEncBody) -> Json<AuthenticationResponse> {
    println!("{:?}", body);
    Json(AuthenticationResponse {
        email: "hello".to_string(),
        password: "world".to_string(),
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
