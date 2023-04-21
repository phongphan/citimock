use crate::extractors::error_response;
use crate::extractors::xml_content_type;
use axum::{
    async_trait,
    body::{Body, Bytes},
    extract::FromRequest,
    http::{Request, StatusCode},
    response::{IntoResponse, Response},
};

pub struct XmlBody(Bytes);

#[async_trait]
impl<S> FromRequest<S, Body> for XmlBody
where
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request(req: Request<Body>, state: &S) -> Result<Self, Self::Rejection> {
        if xml_content_type(&req) {
            let body = Bytes::from_request(req, state)
                .await
                .map_err(|err| err.into_response())?;

            //do_thing_with_request_body(body.clone());

            Ok(Self(body))
        } else {
            Err(error_response(
                StatusCode::BAD_REQUEST,
                "400",
                "invalid content-type",
            ))
        }
    }
}
