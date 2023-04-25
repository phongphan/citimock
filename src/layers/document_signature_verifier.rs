use crate::extractors::error_response;
use crate::services::document_service_utils::serialize_node;
use crate::services::document_service_utils::XMLDocWrapper;
use crate::services::document_service_utils::XmlSecDSigCtxWrapper;
use crate::services::document_service_utils::XmlSecKeysManager;
use crate::xmlsec::xmlFreeNode;
use crate::xmlsec::xmlNodePtr;
use crate::xmlsec::xmlSecDSigCtxVerify;
use crate::xmlsec::xmlSecDSigStatus_xmlSecDSigStatusSucceeded;
use crate::xmlsec::xmlSecKeyDataFormat_xmlSecKeyDataFormatCertPem;
use crate::xmlsec::xmlSecKeyDestroy;
use crate::xmlsec::xmlSecKeySetName;
use crate::xmlsec::xmlSecOpenSSLAppDefaultKeysMngrAdoptKey;
use crate::xmlsec::xmlSecOpenSSLAppDefaultKeysMngrInit;
use crate::xmlsec::xmlSecOpenSSLAppKeyCertLoadMemory;
use crate::xmlsec::xmlSecOpenSSLAppKeyLoadMemory;
use crate::xmlsec::xmlUnlinkNode;
use crate::xmlsec::XMLSEC_KEYINFO_FLAGS_LAX_KEY_SEARCH;
use crate::xmlsec::{xmlDocGetRootElement, xmlSecDSigNs, xmlSecFindNode, xmlSecNodeSignature};
use crate::SessionState;
use crate::VerifyCertPem;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::response::Response;
use futures_util::future::BoxFuture;
use std::ffi::CString;
use std::ptr;
use std::task::{Context, Poll};
use tower::{Layer, Service};

#[derive(Clone)]
pub struct VerifierLayer {}

impl VerifierLayer {
    pub fn new() -> Self {
        println!("creating new VerifierLayer");
        VerifierLayer {}
    }
}

impl<S> Layer<S> for VerifierLayer {
    type Service = VerifierService<S>;

    fn layer(&self, service: S) -> Self::Service {
        VerifierService::new(service)
    }
}

impl Default for VerifierLayer {
    fn default() -> Self {
        Self::new()
    }
}

pub struct VerifierService<T> {
    inner: T,
}

impl<T> VerifierService<T> {
    fn new(inner: T) -> Self {
        println!("creating new VerifierService");
        VerifierService { inner }
    }
}

impl<T: Clone> Clone for VerifierService<T> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<S> Service<Request<Body>> for VerifierService<S>
where
    S: Service<Request<Body>, Response = Response> + Send + 'static + Clone,
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
        let mut inner = self.inner.clone();
        let session = request.extensions().get::<SessionState>().unwrap().clone();
        Box::pin(async move {
            println!("verifying request");
            let (parts, body) = request.into_parts();
            let bytes = match hyper::body::to_bytes(body).await {
                Ok(v) => v,
                Err(err) => {
                    return Ok(error_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "INTERNAL_SERVER_ERROR",
                        &err.to_string(),
                    ))
                }
            };

            let xml = match std::str::from_utf8(&bytes) {
                Ok(v) => v,
                Err(err) => {
                    return Ok(error_response(
                        StatusCode::BAD_REQUEST,
                        "BAD_REQUEST",
                        &err.to_string(),
                    ))
                }
            };

            let verified = match verify_signature(&session.dsig_cert, "dsig-cert", xml) {
                Ok(v) => v,
                Err(err) => {
                    return Ok(error_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "INTERNAL_SERVER_ERROR",
                        &err,
                    ))
                }
            };

            if !verified {
                return Ok(error_response(
                    StatusCode::BAD_REQUEST,
                    "BAD_REQUEST",
                    "invalid signature",
                ));
            };

            let doc = match remove_signature(xml) {
                Ok(v) => v,
                Err(err) => {
                    return Ok(error_response(StatusCode::BAD_REQUEST, "BAD_REQUEST", &err))
                }
            };

            let request = Request::from_parts(parts, doc.into());
            inner.call(request).await
        })
    }
}

fn verify_signature(
    VerifyCertPem(certificate): &VerifyCertPem,
    certificate_name: &str,
    xml: &str,
) -> Result<bool, String> {
    unsafe {
        let doc = XMLDocWrapper::from_xml(xml);
        let root = xmlDocGetRootElement(doc.ptr());
        if doc.ptr().is_null() || root.is_null() {
            return Err("unable to parse XML document".to_owned());
        }

        let manager = XmlSecKeysManager::new();
        if manager.ptr().is_null() {
            return Err("cannot create key manager".to_owned());
        }
        if xmlSecOpenSSLAppDefaultKeysMngrInit(manager.ptr()) < 0 {
            return Err("cannot initialize key manager".to_owned());
        }

        let app_key = xmlSecOpenSSLAppKeyLoadMemory(
            certificate.as_ptr(),
            certificate.len(),
            xmlSecKeyDataFormat_xmlSecKeyDataFormatCertPem,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
        );
        if app_key.is_null() {
            return Err("cannot load certificate as key".to_owned());
        }

        if xmlSecOpenSSLAppKeyCertLoadMemory(
            app_key,
            certificate.as_ptr(),
            certificate.len(),
            xmlSecKeyDataFormat_xmlSecKeyDataFormatCertPem,
        ) < 0
        {
            xmlSecKeyDestroy(app_key);
            return Err("cannot load certificate".to_owned());
        }

        if let Ok(certificate_name) = CString::new(certificate_name) {
            if xmlSecKeySetName(app_key, certificate_name.as_ptr() as *mut u8) < 0 {
                xmlSecKeyDestroy(app_key);
                return Err("failed to set key name for key".to_owned());
            }
        } else {
            xmlSecKeyDestroy(app_key);
            return Err("failed to set key name".to_owned());
        }

        // key manager is responsible to release the app_key
        if xmlSecOpenSSLAppDefaultKeysMngrAdoptKey(manager.ptr(), app_key) < 0 {
            xmlSecKeyDestroy(app_key);
            return Err("failed to adopt encryption certificate".to_owned());
        }

        let sig_node = xmlSecFindNode(root, xmlSecNodeSignature.as_ptr(), xmlSecDSigNs.as_ptr());
        if sig_node.is_null() {
            return Err("failed to find encryption node".to_owned());
        }

        let ctx = XmlSecDSigCtxWrapper::new_with_manager(&manager);

        // allow unnamed cert to be picked up
        (*ctx.ptr()).keyInfoReadCtx.flags |= XMLSEC_KEYINFO_FLAGS_LAX_KEY_SEARCH;
        (*ctx.ptr()).keyInfoWriteCtx.flags |= XMLSEC_KEYINFO_FLAGS_LAX_KEY_SEARCH;

        if xmlSecDSigCtxVerify(ctx.ptr(), sig_node) < 0 {
            return Err("failed to verify signature".to_owned());
        }

        Ok((*ctx.ptr()).status == xmlSecDSigStatus_xmlSecDSigStatusSucceeded)
    }
}

fn remove_signature(xml: &str) -> Result<String, String> {
    unsafe {
        let doc = XMLDocWrapper::from_xml(xml);
        let root = xmlDocGetRootElement(doc.ptr());
        if doc.ptr().is_null() || root.is_null() {
            return Err("unable to parse XML document".to_owned());
        }

        let sig_node = xmlSecFindNode(root, xmlSecNodeSignature.as_ptr(), xmlSecDSigNs.as_ptr());
        if sig_node.is_null() {
            return Ok(xml.to_owned());
        }
        xmlUnlinkNode(sig_node);
        xmlFreeNode(sig_node);

        serialize_node(&(doc.ptr() as xmlNodePtr)).map_err(|err| err.to_string())
    }
}
