use crate::handlers::authentication::AuthenticationError;
use crate::models::errors::CommonErrorResponse;

use axum::{
    async_trait,
    body::Body,
    extract::FromRequest,
    http::{header, HeaderValue, Request, StatusCode},
    response::{IntoResponse, Response},
};

use yaserde;

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
        yaserde::ser::to_string(&CommonErrorResponse {
            http_code: code.to_owned(),
            http_message: message.to_owned(),
            information: message.to_owned(),
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
