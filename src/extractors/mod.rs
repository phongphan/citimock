use crate::models::errors::CommonErrorResponse;
use axum::{
    body::Body,
    http::{header, Request, StatusCode},
    response::{IntoResponse, Response},
};
use hyper::header::HeaderValue;

pub mod basic_auth;
pub mod xml;
pub mod xml_plain;

pub fn xml_content_type(request: &Request<Body>) -> bool {
    let content_type_header = request.headers().get(header::CONTENT_TYPE);
    let content_type = content_type_header.and_then(|value| value.to_str().ok());

    if let Some(content_type) = content_type {
        content_type.starts_with("application/xml") || content_type.starts_with("text/xml")
    } else {
        false
    }
}

pub fn error_response(status_code: StatusCode, code: &str, message: &str) -> Response {
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
