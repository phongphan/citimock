use crate::services::document_service_utils::serialize_node;
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
use crate::xmlsec::xmlSecOpenSSLKeyDataDesGetKlass;
use axum::body::Body;
use axum::http::{header, HeaderValue, Request, StatusCode};
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
            let response: Response = future.await?;
            let (_parts, body) = response.into_parts();
            let bytes = hyper::body::to_bytes(body)
                .await
                .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response())
                .unwrap();

            let xml = std::str::from_utf8(&bytes).unwrap();
            let signed_doc = encrypt(
                &certificate.template,
                &certificate.certificate,
                &certificate.certificate_name,
                xml,
            )
            .unwrap();
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

        let manager = XmlSecKeysManager::new(); //xmlSecKeysMngrCreate();
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
                return Err("failed to set key name for key".to_owned());
            }
        } else {
            return Err("failed to set key name".to_owned());
        }

        if xmlSecOpenSSLAppDefaultKeysMngrAdoptKey(manager.ptr(), app_key) < 0 {
            xmlSecKeyDestroy(app_key);
            return Err("failed to adopt encryption certificate".to_owned());
        }

        let ctx = XmlSecEncCtx::new(&manager); // FIXME: xmlSecEncCtxCreate(manager.ptr());
        if ctx.ptr().is_null() {
            return Err("cannot create encryption context".to_owned());
        }

        (*ctx.ptr()).encKey = create_xmlsec_key();
        if (*ctx.ptr()).encKey.is_null() {
            return Err("cannot create encryption key".to_owned());
        }

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

        Ok(serialize_node(&(doc.ptr() as xmlNodePtr)).unwrap())
    }
}

fn create_xmlsec_key() -> xmlSecKeyPtr {
    /*switch (cipher_type) {
    case SESSION_CIPHER_AES128CBC:
        return xmlSecKeyGenerate(xmlSecKeyDataAesId, 128, xmlSecKeyDataTypeSession);
    case SESSION_CIPHER_AES192CBC:
        return xmlSecKeyGenerate(xmlSecKeyDataAesId, 192, xmlSecKeyDataTypeSession);
    case SESSION_CIPHER_AES256CBC:
        return xmlSecKeyGenerate(xmlSecKeyDataAesId, 256, xmlSecKeyDataTypeSession);
    case SESSION_CIPHER_DES3CBC:
        return xmlSecKeyGenerate(xmlSecKeyDataDesId, 192, xmlSecKeyDataTypeSession);
    default:
        return NULL;
    }*/
    unsafe {
        xmlSecKeyGenerate(
            xmlSecOpenSSLKeyDataDesGetKlass(),
            192,
            xmlSecKeyDataTypeSession,
        )
    }
}