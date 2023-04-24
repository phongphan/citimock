use crate::extractors::xml::Xml;
use crate::services::jwt_service::encrypt_token;
use crate::{AppState, SessionState};
use axum::{
    extract::State,
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Extension,
};
use std::sync::Arc;
use std::time::Duration;
use yaserde;
use yaserde_derive::{YaDeserialize, YaSerialize};

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
    Extension(session): Extension<SessionState>,
    Xml(body): Xml<AuthenticationRequest>,
) -> Result<Xml<AuthenticationResponse>, Response> {
    println!("body: {:?}", body);
    println!("auth_type: {:?}", session.auth_type);
    println!("session client: {}", session.client_id);
    if !(session.authenticated && session.auth_type == "basic") {
        return Err(
            error_response(StatusCode::UNAUTHORIZED, "400", "UNAUTHORIZED").into_response(),
        );
    }

    match encrypt_token(
        &state.jwt_pub,
        &session.client_id,
        "2",
        Duration::from_secs(30 * 60),
    ) {
        Ok(token) => {
            println!("token: {}", token);
            Ok(Xml(AuthenticationResponse {
                token_type: "client_credentials".to_owned(),
                access_token: token,
                scope: "/authenticationservices/v1".to_owned(),
                expires_in: 1800,
            }))
        }
        Err(err) => Err(error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "500",
            err.to_string().as_str(),
        )
        .into_response()),
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
