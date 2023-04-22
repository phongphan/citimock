use crate::extractors::error_response;
use crate::services::document_service_utils::serialize_node;
use crate::services::document_service_utils::SessionCipher;
use crate::services::document_service_utils::XMLDocWrapper;
use crate::services::document_service_utils::XmlSecEncCtx;
use crate::services::document_service_utils::XmlSecKeysManager;
use crate::xmlsec::xmlDocGetRootElement;
use crate::xmlsec::xmlNodePtr;
use crate::xmlsec::xmlSecEncCtxXmlEncrypt;
use crate::xmlsec::xmlSecEncNs;
use crate::xmlsec::xmlSecFindNode;
use crate::xmlsec::xmlSecKeyDataFormat_xmlSecKeyDataFormatCertPem;
use crate::xmlsec::xmlSecKeyDataTypeSession;
use crate::xmlsec::xmlSecKeyDestroy;
use crate::xmlsec::xmlSecKeyGenerate;
use crate::xmlsec::xmlSecKeyPtr;
use crate::xmlsec::xmlSecKeySetName;
use crate::xmlsec::xmlSecNodeEncryptedData;
use crate::xmlsec::xmlSecOpenSSLAppDefaultKeysMngrAdoptKey;
use crate::xmlsec::xmlSecOpenSSLAppDefaultKeysMngrInit;
use crate::xmlsec::xmlSecOpenSSLAppKeyCertLoadMemory;
use crate::xmlsec::xmlSecOpenSSLAppKeyLoadMemory;
use crate::xmlsec::xmlSecOpenSSLKeyDataAesGetKlass;
use crate::xmlsec::xmlSecOpenSSLKeyDataDesGetKlass;
use crate::xmlsec::XMLSEC_KEYINFO_FLAGS_LAX_KEY_SEARCH;
use axum::body::{self, Body};
use axum::http::{Request, StatusCode};
use axum::response::Response;
use futures_util::future::BoxFuture;
use std::ffi::CString;
use std::ptr;
use std::task::{Context, Poll};
use tower::{Layer, Service};

#[derive(Clone)]
struct Certificate {
    certificate: String,
    certificate_name: String,
    template: String,
}

#[derive(Clone)]
pub struct EncryptionLayer {
    certificate: Certificate,
}

impl EncryptionLayer {
    pub fn new(certificate: &str, certificate_name: &str, template: &str) -> Self {
        println!("creating new EncryptionLayer");
        EncryptionLayer {
            certificate: Certificate {
                certificate: certificate.to_owned(),
                certificate_name: certificate_name.to_owned(),
                template: template.to_owned(),
            },
        }
    }
}

impl<S> Layer<S> for EncryptionLayer {
    type Service = EncryptionService<S>;

    fn layer(&self, service: S) -> Self::Service {
        EncryptionService::new(service, self.certificate.clone())
    }
}

pub struct EncryptionService<T> {
    inner: T,
    certificate: Certificate,
}

impl<T> EncryptionService<T> {
    fn new(inner: T, certificate: Certificate) -> Self {
        println!("creating new EncryptionService");
        EncryptionService { inner, certificate }
    }
}

impl<T: Clone> Clone for EncryptionService<T> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            certificate: self.certificate.clone(),
        }
    }
}

impl<S> Service<Request<Body>> for EncryptionService<S>
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
        let certificate = self.certificate.clone();
        let future = self.inner.call(request);
        Box::pin(async move {
            println!("entering encryptiion service");
            let response: Response = future.await?;
            println!("encrypting response");
            let (parts, body) = response.into_parts();
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

            let encrypted_doc = match encrypt(
                &certificate.template,
                &certificate.certificate,
                &certificate.certificate_name,
                xml,
            ) {
                Ok(v) => v,
                Err(err) => {
                    return Ok(error_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "INTERNAL_SERVER_ERROR",
                        &err,
                    ))
                }
            };

            Ok(Response::from_parts(parts, body::boxed(encrypted_doc)))
        })
    }
}

pub fn encrypt(
    template: &str,
    cert: &str,
    certificate_name: &str,
    xml: &str,
) -> Result<String, String> {
    unsafe {
        let doc = XMLDocWrapper::from_xml(xml);
        let root = xmlDocGetRootElement(doc.ptr());
        if doc.ptr().is_null() || root.is_null() {
            return Err("unable to parse XML document".to_owned());
        }

        let template_doc = XMLDocWrapper::from_xml(template);
        let template_root = xmlDocGetRootElement(template_doc.ptr());
        if template_doc.ptr().is_null() || template_root.is_null() {
            return Err("unable to parse XML template".to_owned());
        }

        let manager = XmlSecKeysManager::new();
        if manager.ptr().is_null() {
            return Err("cannot create key manager".to_owned());
        }
        if xmlSecOpenSSLAppDefaultKeysMngrInit(manager.ptr()) < 0 {
            return Err("cannot initialize key manager".to_owned());
        }

        let app_key = xmlSecOpenSSLAppKeyLoadMemory(
            cert.as_ptr(),
            cert.len(),
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
            cert.as_ptr(),
            cert.len(),
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

        let ctx = XmlSecEncCtx::new(&manager);
        if ctx.ptr().is_null() {
            return Err("cannot create encryption context".to_owned());
        }

        (*ctx.ptr()).encKey = create_xmlsec_key(SessionCipher::SessionCipherDes3cbc);
        if (*ctx.ptr()).encKey.is_null() {
            return Err("cannot create encryption key".to_owned());
        }

        // allow unnamed cert to be picked up
        (*ctx.ptr()).keyInfoReadCtx.flags |= XMLSEC_KEYINFO_FLAGS_LAX_KEY_SEARCH;
        (*ctx.ptr()).keyInfoWriteCtx.flags |= XMLSEC_KEYINFO_FLAGS_LAX_KEY_SEARCH;

        let enc_data_node = xmlSecFindNode(
            template_root,
            xmlSecNodeEncryptedData.as_ptr(),
            xmlSecEncNs.as_ptr(),
        );
        if enc_data_node.is_null() {
            return Err("failed to find encryption node".to_owned());
        }

        if xmlSecEncCtxXmlEncrypt(ctx.ptr(), enc_data_node, root) < 0 {
            return Err("failed to encrypt xml body".to_owned());
        }

        serialize_node(&(doc.ptr() as xmlNodePtr)).map_err(|err| err.to_string())
    }
}

fn create_xmlsec_key(cipher: SessionCipher) -> xmlSecKeyPtr {
    unsafe {
        match cipher {
            SessionCipher::SessionCipherAes128cbc => xmlSecKeyGenerate(
                xmlSecOpenSSLKeyDataAesGetKlass(),
                128,
                xmlSecKeyDataTypeSession,
            ),
            SessionCipher::SessionCipherAes192cbc => xmlSecKeyGenerate(
                xmlSecOpenSSLKeyDataAesGetKlass(),
                192,
                xmlSecKeyDataTypeSession,
            ),
            SessionCipher::SessionCipherAes256cbc => xmlSecKeyGenerate(
                xmlSecOpenSSLKeyDataAesGetKlass(),
                256,
                xmlSecKeyDataTypeSession,
            ),
            SessionCipher::SessionCipherDes3cbc => xmlSecKeyGenerate(
                xmlSecOpenSSLKeyDataDesGetKlass(),
                192,
                xmlSecKeyDataTypeSession,
            ),
        }
    }
}
