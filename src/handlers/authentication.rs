use crate::extractors::basic_auth::ExtractBasicAuth;
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

#[derive(Debug, Clone, Copy, Default)]
pub struct Xml<T>(pub T);

#[async_trait]
impl<S, T> FromRequest<S, Body> for Xml<T>
where
    S: Send + Sync,
    T: yaserde::YaDeserialize,
{
    type Rejection = Response;

    async fn from_request(req: Request<Body>, state: &S) -> Result<Self, Self::Rejection> {
        if xml_content_type(&req) {
            match String::from_request(req, state)
                .await
                .map_err(|_| (StatusCode::BAD_REQUEST, "cannot extract request body"))
                .and_then(|s| {
                    yaserde::de::from_str(&s)
                        .map_err(|_| (StatusCode::BAD_REQUEST, "invalid input XML"))
                }) {
                Ok(value) => Ok(Self(value)),
                Err((status_code, message)) => Err(error_response(status_code, "400", message)),
            }
        } else {
            Err(error_response(
                StatusCode::BAD_REQUEST,
                "400",
                "invalid content-type",
            ))
        }
    }
}

fn xml_content_type(request: &Request<Body>) -> bool {
    let content_type_header = request.headers().get(header::CONTENT_TYPE);
    let content_type = content_type_header.and_then(|value| value.to_str().ok());

    if let Some(content_type) = content_type {
        content_type.starts_with("application/xml") || content_type.starts_with("text/xml")
    } else {
        false
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

impl<T> IntoResponse for Xml<T>
where
    T: yaserde::YaSerialize,
{
    fn into_response(self) -> Response {
        match yaserde::ser::to_string(&self.0) {
            Ok(body) => (
                [(
                    header::CONTENT_TYPE,
                    HeaderValue::from_static("application/xml"),
                )],
                body,
            )
                .into_response(),
            Err(err) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                [(
                    header::CONTENT_TYPE,
                    HeaderValue::from_static("application/xml"),
                )],
                yaserde::ser::to_string(&AuthenticationError {
                    code: "500".to_owned(),
                    message: err,
                })
                .unwrap(),
            )
                .into_response(),
        }
    }
}
