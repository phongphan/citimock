use axum::body::Body;
use axum::http::{header, HeaderValue, Request, StatusCode};
use axum::response::{IntoResponse, Response};
use std::task::{Context, Poll};

use crate::services::document_service_utils::parse_xml;
use crate::services::document_service_utils::serialize_node;
use crate::services::document_service_utils::XMLDocWrapper;
use crate::services::document_service_utils::XmlSecDSigCtxWrapper;
use crate::xmlsec::xmlAddChild;
use crate::xmlsec::xmlNodePtr;
use crate::xmlsec::xmlSecDSigCtxSign;
use crate::xmlsec::xmlSecKeyDataFormat_xmlSecKeyDataFormatPem;
use crate::xmlsec::xmlSecKeySetName;
use crate::xmlsec::xmlSecOpenSSLAppKeyLoadMemory;
use crate::xmlsec::{xmlDocGetRootElement, xmlSecDSigNs, xmlSecFindNode, xmlSecNodeSignature};

use std::ffi::CString;
use std::ptr;

use tower::{Layer, Service};

use futures_util::future::BoxFuture;

#[derive(Clone)]
pub struct Key {
    key: String,
    key_name: String,
    template: String,
}

#[derive(Clone)]
pub struct SigningLayer {
    key: Key,
}

impl SigningLayer {
    pub fn new(key: &str, key_name: &str, template: &str) -> Self {
        println!("creating new SigningLayer");
        SigningLayer {
            key: Key {
                key: key.to_owned(),
                key_name: key_name.to_owned(),
                template: template.to_owned(),
            },
        }
    }
}

impl<S> Layer<S> for SigningLayer {
    type Service = SigningService<S>;

    fn layer(&self, service: S) -> Self::Service {
        SigningService::new(service, self.key.clone())
    }
}

pub struct SigningService<T> {
    inner: T,
    key: Key,
}

impl<T> SigningService<T> {
    pub fn new(inner: T, key: Key) -> Self {
        println!("creating new SigningService");
        SigningService { inner, key }
    }
}

impl<S> Service<Request<Body>> for SigningService<S>
where
    S: Service<Request<Body>, Response = Response> + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    // `BoxFuture` is a type alias for `Pin<Box<dyn Future + Send + 'a>>`
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: Request<Body>) -> Self::Future {
        let key = self.key.clone();
        let future = self.inner.call(request);
        Box::pin(async move {
            let response: Response = future.await?;
            let (_parts, body) = response.into_parts();
            let bytes = hyper::body::to_bytes(body)
                .await
                .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response())
                .unwrap();

            let xml = std::str::from_utf8(&bytes).unwrap();
            let signed_doc = sign(&key.template, &key.key, &key.key_name, xml).unwrap();
            Ok((
                [(
                    header::CONTENT_TYPE,
                    HeaderValue::from_static("application/xml"),
                )],
                signed_doc,
            )
                .into_response())
        })
    }
}

impl<T: Clone> Clone for SigningService<T> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            key: self.key.clone(),
        }
    }
}

pub fn sign(template: &str, key: &str, key_name: &str, xml: &str) -> Result<String, String> {
    unsafe {
        let doc = XMLDocWrapper::from_xml(xml);
        let root = xmlDocGetRootElement(doc.ptr());
        if doc.ptr().is_null() || root.is_null() {
            return Err("unable to parse XML document".to_owned());
        }

        let template_doc = parse_xml(template);
        let template_root = xmlDocGetRootElement(template_doc);
        if template_doc.is_null() || template_root.is_null() {
            return Err("unable to parse XML template".to_owned());
        }

        xmlAddChild(root, template_root);

        let sec_node = xmlSecFindNode(root, xmlSecNodeSignature.as_ptr(), xmlSecDSigNs.as_ptr());
        let ctx = XmlSecDSigCtxWrapper::new();
        (*ctx.ptr()).signKey = xmlSecOpenSSLAppKeyLoadMemory(
            key.as_ptr(),
            key.len(),
            xmlSecKeyDataFormat_xmlSecKeyDataFormatPem,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
        );
        if (*ctx.ptr()).signKey.is_null() {
            return Err("failed to load private pem key".to_owned());
        }

        if let Ok(key_name) = CString::new(key_name) {
            if xmlSecKeySetName((*ctx.ptr()).signKey, key_name.as_ptr() as *mut u8) < 0 {
                return Err("failed to set key name for key".to_owned());
            }
        } else {
            return Err("failed to set key name".to_owned());
        }

        if xmlSecDSigCtxSign(ctx.ptr(), sec_node) < 0 {
            return Err("signature failed".to_owned());
        }

        Ok(serialize_node(&(doc.ptr() as xmlNodePtr)).unwrap())
    }
}
