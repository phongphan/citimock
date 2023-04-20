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
