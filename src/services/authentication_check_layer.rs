use crate::handlers::authentication::AuthenticationError;
use crate::SessionState;
use axum::body::Body;
use axum::middleware::Next;
use axum::{
    http::{header, HeaderValue, Request, StatusCode},
    response::{IntoResponse, Response},
};

pub async fn authentication_check_layer(
    request: Request<Body>,
    next: Next<Body>,
) -> Result<impl IntoResponse, Response> {
    let session = request.extensions().get::<SessionState>().unwrap();
    if session.authenticated {
        Ok(next.run(request).await)
    } else {
        println!("NOT AUTHENTICATED!!!!!");
        Err(error_response(
            StatusCode::UNAUTHORIZED,
            "401",
            "UNAUTHORIZED",
        ))
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
