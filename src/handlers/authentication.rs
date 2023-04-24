use crate::extractors::basic_auth::ExtractBasicAuth;
use crate::extractors::xml::Xml;
use crate::services::jwt_service::encrypt_token;
use crate::AppState;
use axum::{
    extract::State,
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
};
use libpasta;
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
    ExtractBasicAuth((user, password)): ExtractBasicAuth,
    Xml(body): Xml<AuthenticationRequest>,
    //XmlEncBody(body): XmlEncBody,
) -> Result<Xml<AuthenticationResponse>, Response> {
    println!("user: {:?}", user);
    println!("body: {:?}", body);
    match crate::services::client_service::get_client_by_uid(&state.pool, &user).await {
        Ok(client) => {
            println!("{:?}", client);
            if libpasta::verify_password(client.hash(), &password) {
                let token = encrypt_token(&state.jwt_pub, &user, "2", Duration::from_secs(30 * 60))
                    .unwrap();
                Ok(Xml(AuthenticationResponse {
                    token_type: "client_credentials".to_owned(),
                    access_token: token,
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
