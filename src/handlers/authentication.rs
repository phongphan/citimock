use crate::extractors::basic_auth::ExtractBasicAuth;
use crate::extractors::xml::Xml;
use crate::AppState;
use axum::{
    async_trait,
    body::{Body, Bytes},
    extract::{FromRequest, State},
    http::{header, HeaderValue, Request, StatusCode},
    response::{IntoResponse, Response},
};
use std::sync::Arc;
use yaserde;
use yaserde_derive::{YaDeserialize, YaSerialize};

use libpasta;

#[derive(Debug, YaDeserialize)]
#[yaserde(
    prefix = "defaultns",
    default_namesapce = "defaultns",
    namespace = "defaultns: http://com.citi.citiconnect/services/types/oauthtoken/v1",
    rename = "oAuthToken"
)]
pub struct AuthenticationRequest {
    #[yaserde(attribute, rename = "grantType", prefix = "defaultns")]
    pub grant_type: String,
    #[yaserde(attribute, rename = "scope", prefix = "defaultns")]
    pub scope: String,
    #[yaserde(attribute, rename = "sourceApplication", prefix = "defaultns")]
    pub source_application: String,
}

#[derive(Debug, YaSerialize)]
#[yaserde(rename = "token")]
pub struct AuthenticationResponse {
    pub token_type: String,
    pub access_token: String,
    pub expires_in: u32,
    pub scope: String,
}

#[derive(Debug, YaSerialize)]
#[yaserde(rename = "loginResponse")]
pub struct AuthenticationError {
    #[yaserde(rename = "statusCode")]
    pub code: String,

    #[yaserde(rename = "statusMessage")]
    pub message: String,
}

pub async fn authentication_v2(
    State(state): State<Arc<AppState>>,
    ExtractBasicAuth((user, password)): ExtractBasicAuth,
    Xml(body): Xml<AuthenticationRequest>,
    //XmlEncBody(body): XmlEncBody,
) -> Result<Xml<AuthenticationResponse>, Response> {
    println!("user: {:?}", user);
    println!("body: {:?}", body);
    match crate::services::client_service::get_client_by_id(&state.pool, &user).await {
        Ok(client) => {
            println!("{:?}", client);
            if libpasta::verify_password(client.hash(), &password) {
                Ok(Xml(AuthenticationResponse {
                    token_type: "client_credentials".to_owned(),
                    access_token: "thisistoken".to_owned(),
                    scope: "/authenticationservices/v1".to_owned(),
                    expires_in: 1800,
                }))
            } else {
                Err(error_response(StatusCode::UNAUTHORIZED, "401", "UNAUTHORIZED").into_response())
            }
        }
        Err(sqlx::Error::RowNotFound) => {
            Err(error_response(StatusCode::FORBIDDEN, "403", "Client is forbidden").into_response())
        }
        Err(err) => {
            println!("{:?}", err);
            Err(error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "500",
                "INTERNAL_SERVER_ERROR",
            )
            .into_response())
        }
    }
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

fn error_response(status_code: StatusCode, code: &str, message: &str) -> Response {
    (
        status_code,
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/xml"),
        )],
        yaserde::ser::to_string(&AuthenticationError {
            code: code.to_owned(),
            message: message.to_owned(),
        })
        .unwrap(),
    )
        .into_response()
}
