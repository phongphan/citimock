use crate::extractors::error_response;
use crate::services::document_service_utils::serialize_node;
use crate::services::document_service_utils::XMLDocWrapper;
use crate::services::document_service_utils::XmlSecEncCtx;
use crate::services::document_service_utils::XmlSecKeysManager;
use crate::xmlsec::xmlDocGetRootElement;
use crate::xmlsec::xmlNodePtr;
use crate::xmlsec::xmlSecEncCtxDecrypt;
use crate::xmlsec::xmlSecEncNs;
use crate::xmlsec::xmlSecFindNode;
use crate::xmlsec::xmlSecKeyDataFormat_xmlSecKeyDataFormatPem;
use crate::xmlsec::xmlSecKeyDestroy;
use crate::xmlsec::xmlSecKeySetName;
use crate::xmlsec::xmlSecNodeEncryptedData;
use crate::xmlsec::xmlSecOpenSSLAppDefaultKeysMngrAdoptKey;
use crate::xmlsec::xmlSecOpenSSLAppDefaultKeysMngrInit;
use crate::xmlsec::xmlSecOpenSSLAppKeyLoadMemory;
use crate::xmlsec::XMLSEC_KEYINFO_FLAGS_LAX_KEY_SEARCH;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::response::Response;
use futures_util::future::BoxFuture;
use std::ffi::CString;
use std::ptr;
use std::task::{Context, Poll};
use tower::{Layer, Service};

#[derive(Clone)]
struct Key {
    key: String,
    key_name: String,
}

#[derive(Clone)]
pub struct DecryptionLayer {
    key: Key,
}

impl DecryptionLayer {
    pub fn new(key: &str, key_name: &str) -> Self {
        println!("creating new DecryptionLayer");
        DecryptionLayer {
            key: Key {
                key: key.to_owned(),
                key_name: key_name.to_owned(),
            },
        }
    }
}

impl<S> Layer<S> for DecryptionLayer {
    type Service = DecryptionService<S>;

    fn layer(&self, service: S) -> Self::Service {
        DecryptionService::new(service, self.key.clone())
    }
}

pub struct DecryptionService<T> {
    inner: T,
    key: Key,
}

impl<T> DecryptionService<T> {
    fn new(inner: T, key: Key) -> Self {
        println!("creating new DecryptionService");
        DecryptionService { inner, key }
    }
}

impl<T: Clone> Clone for DecryptionService<T> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            key: self.key.clone(),
        }
    }
}

impl<S> Service<Request<Body>> for DecryptionService<S>
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
        let key = self.key.clone();
        Box::pin(async move {
            println!("decrypting request");
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
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "INTERNAL_SERVER_ERROR",
                        &err.to_string(),
                    ))
                }
            };
            let decrypted_doc = match decrypt(&key.key, &key.key_name, xml) {
                Ok(v) => v,
                Err(err) => {
                    return Ok(error_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "INTERNAL_SERVER_ERROR",
                        &err,
                    ))
                }
            };

            let request = Request::from_parts(parts, decrypted_doc.into());
            inner.call(request).await
        })
    }
}

pub fn decrypt(key: &str, key_name: &str, xml: &str) -> Result<String, String> {
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
            key.as_ptr(),
            key.len(),
            xmlSecKeyDataFormat_xmlSecKeyDataFormatPem,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
        );
        if app_key.is_null() {
            return Err("cannot load decryption key".to_owned());
        }

        if let Ok(key_name) = CString::new(key_name) {
            if xmlSecKeySetName(app_key, key_name.as_ptr() as *mut u8) < 0 {
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
            return Err("failed to adopt decryption key".to_owned());
        }

        let ctx = XmlSecEncCtx::new(&manager);
        if ctx.ptr().is_null() {
            return Err("cannot create decryption context".to_owned());
        }

        // allow unnamed key to be picked up
        (*ctx.ptr()).keyInfoReadCtx.flags |= XMLSEC_KEYINFO_FLAGS_LAX_KEY_SEARCH;
        (*ctx.ptr()).keyInfoWriteCtx.flags |= XMLSEC_KEYINFO_FLAGS_LAX_KEY_SEARCH;

        let enc_data_node =
            xmlSecFindNode(root, xmlSecNodeEncryptedData.as_ptr(), xmlSecEncNs.as_ptr());
        if enc_data_node.is_null() {
            return Err("failed to find encryption node".to_owned());
        }

        if xmlSecEncCtxDecrypt(ctx.ptr(), enc_data_node) < 0 {
            return Err("failed to decrypt xml body".to_owned());
        }

        serialize_node(&(doc.ptr() as xmlNodePtr)).map_err(|err| err.to_string())
    }
}
