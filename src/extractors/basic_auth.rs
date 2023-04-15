use axum::{
    async_trait,
    extract::FromRequestParts,
    http::{header::AUTHORIZATION, request::Parts, StatusCode},
};
use base64::{engine::general_purpose, Engine as _};
use itertools::Itertools;

pub type Rejection = (StatusCode, &'static str);

#[derive(Debug)]
pub struct ExtractBasicAuth(pub (String, String));

#[async_trait]
impl<S> FromRequestParts<S> for ExtractBasicAuth
where
    S: Send + Sync,
{
    type Rejection = (StatusCode, &'static str);

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        if let Ok(authorization) = get_header(parts, StatusCode::BAD_REQUEST) {
            authorization
                .strip_prefix("Basic ")
                .ok_or((
                    StatusCode::BAD_REQUEST,
                    "`Authorization` is not Basic Authorization",
                ))
                .and_then(|basic| {
                    general_purpose::STANDARD
                        .decode(basic)
                        .map_err(|_| (StatusCode::BAD_REQUEST, "`Authorization` cannot decoded"))
                })
                .and_then(|decoded| {
                    String::from_utf8(decoded).map_err(|_| {
                        (
                            StatusCode::BAD_REQUEST,
                            "`Authorization` contains invalid utf-8 sequence",
                        )
                    })
                })
                .and_then(|s| {
                    s.split(':').map(|x| x.to_owned()).collect_tuple().ok_or((
                        StatusCode::BAD_REQUEST,
                        "`Authorization` expected two elements",
                    ))
                })
                .map(|(user, password)| ExtractBasicAuth((user, password)))
        } else {
            Err((StatusCode::BAD_REQUEST, "`Authorization` header is missing"))
        }
    }
}

fn get_header(parts: &mut Parts, status_code: StatusCode) -> Result<&str, Rejection> {
    parts
        .headers
        .get(AUTHORIZATION)
        .ok_or((status_code, "`Authorization` header is missing"))?
        .to_str()
        .map_err(|_| {
            (
                status_code,
                "`Authorization` header contains invalid characters",
            )
        })
}
