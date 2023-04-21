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
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::response::{IntoResponse, Response};
use futures_util::future::BoxFuture;
use std::ffi::CString;
use std::ptr;
use std::task::{Context, Poll};
use tower::{Layer, Service};

#[derive(Clone)]
struct Certificate {
    certificate: String,
    certificate_name: String,
}

#[derive(Clone)]
pub struct VerifierLayer {
    certificate: Certificate,
}

impl VerifierLayer {
    pub fn new(certificate: &str, certificate_name: &str) -> Self {
        println!("creating new VerifierLayer");
        VerifierLayer {
            certificate: Certificate {
                certificate: certificate.to_owned(),
                certificate_name: certificate_name.to_owned(),
            },
        }
    }
}

impl<S> Layer<S> for VerifierLayer {
    type Service = VerifierService<S>;

    fn layer(&self, service: S) -> Self::Service {
        VerifierService::new(service, self.certificate.clone())
    }
}

pub struct VerifierService<T> {
    inner: T,
    certificate: Certificate,
}

impl<T> VerifierService<T> {
    fn new(inner: T, certificate: Certificate) -> Self {
        println!("creating new VerifierService");
        VerifierService { inner, certificate }
    }
}

impl<T: Clone> Clone for VerifierService<T> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            certificate: self.certificate.clone(),
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
        let certificate = self.certificate.clone();
        Box::pin(async move {
            let (parts, body) = request.into_parts();
            let bytes = hyper::body::to_bytes(body)
                .await
                .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response())
                .unwrap();

            let xml = std::str::from_utf8(&bytes).unwrap();
            let verified =
                verify_signature(&certificate.certificate, &certificate.certificate_name, xml)
                    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err).into_response())
                    .unwrap();
            if !verified {
                panic!("verify signature failed");
            }

            let doc = remove_signature(xml).unwrap();
            let request = Request::from_parts(parts, doc.into());
            inner.call(request).await
        })
    }
}

fn verify_signature(certificate: &str, certificate_name: &str, xml: &str) -> Result<bool, String> {
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
                return Err("failed to set key name for key".to_owned());
            }
        } else {
            return Err("failed to set key name".to_owned());
        }

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

        Ok(serialize_node(&(doc.ptr() as xmlNodePtr)).unwrap())
    }
}
