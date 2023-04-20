use crate::xmlsec::xmlBufferCreate;
use crate::xmlsec::xmlBufferFree;
use crate::xmlsec::xmlBufferPtr;
use crate::xmlsec::xmlDocPtr;
use crate::xmlsec::xmlFreeDoc;
use crate::xmlsec::xmlNodeDump;
use crate::xmlsec::xmlNodePtr;
use crate::xmlsec::xmlParseDoc;
use crate::xmlsec::xmlSecDSigCtxCreate;
use crate::xmlsec::xmlSecDSigCtxDestroy;
use crate::xmlsec::xmlSecDSigCtxPtr;
use crate::xmlsec::xmlSecEncCtxCreate;
use crate::xmlsec::xmlSecEncCtxDestroy;
use crate::xmlsec::xmlSecEncCtxPtr;
use crate::xmlsec::xmlSecKeysMngrCreate;
use crate::xmlsec::xmlSecKeysMngrDestroy;
use crate::xmlsec::xmlSecKeysMngrPtr;
use std::ffi::CStr;
use std::ffi::CString;
use std::ptr;

pub fn parse_xml(doc: &str) -> xmlDocPtr {
    let cstr = CString::new(doc).unwrap();
    unsafe { xmlParseDoc(cstr.as_ptr() as *const u8) }
}

pub fn serialize_node(node: &xmlNodePtr) -> Result<String, Box<dyn std::error::Error>> {
    let buffer = XmlBuffer::new();
    if unsafe { xmlNodeDump(buffer.ptr(), ptr::null_mut(), *node, 0, 0) } < 0 {
        // TODO
    }
    let s = unsafe { CStr::from_ptr((*buffer.ptr).content as *mut i8) };
    Ok(s.to_str()?.to_owned())
}

pub struct XMLDocWrapper {
    ptr: xmlDocPtr,
}

impl XMLDocWrapper {
    pub fn from_xml(doc: &str) -> Self {
        XMLDocWrapper {
            ptr: parse_xml(doc),
        }
    }

    pub fn from_ptr(doc: xmlDocPtr) -> Self {
        XMLDocWrapper { ptr: doc }
    }

    pub fn ptr(&self) -> xmlDocPtr {
        self.ptr
    }
}

impl Drop for XMLDocWrapper {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            unsafe { xmlFreeDoc(self.ptr) }
        }
    }
}

pub struct XmlSecDSigCtxWrapper {
    ptr: xmlSecDSigCtxPtr,
}

impl XmlSecDSigCtxWrapper {
    pub fn new() -> Self {
        XmlSecDSigCtxWrapper {
            ptr: unsafe { xmlSecDSigCtxCreate(ptr::null_mut()) },
        }
    }

    pub fn ptr(&self) -> xmlSecDSigCtxPtr {
        self.ptr
    }
}

impl Default for XmlSecDSigCtxWrapper {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for XmlSecDSigCtxWrapper {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            unsafe { xmlSecDSigCtxDestroy(self.ptr) }
        }
    }
}

pub struct XmlBuffer {
    ptr: xmlBufferPtr,
}

impl XmlBuffer {
    fn new() -> Self {
        XmlBuffer {
            ptr: unsafe { xmlBufferCreate() },
        }
    }

    pub fn ptr(&self) -> xmlBufferPtr {
        self.ptr
    }
}

impl Default for XmlBuffer {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for XmlBuffer {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            unsafe { xmlBufferFree(self.ptr) }
        }
    }
}

pub struct XmlSecKeysManager {
    ptr: xmlSecKeysMngrPtr,
}

impl XmlSecKeysManager {
    pub fn new() -> Self {
        XmlSecKeysManager {
            ptr: unsafe { xmlSecKeysMngrCreate() },
        }
    }

    pub fn ptr(&self) -> xmlSecKeysMngrPtr {
        self.ptr
    }
}

impl Default for XmlSecKeysManager {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for XmlSecKeysManager {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            unsafe { xmlSecKeysMngrDestroy(self.ptr) }
        }
    }
}

pub struct XmlSecEncCtx {
    ptr: xmlSecEncCtxPtr,
}

impl XmlSecEncCtx {
    pub fn new(manager: &XmlSecKeysManager) -> Self {
        XmlSecEncCtx {
            ptr: unsafe { xmlSecEncCtxCreate(manager.ptr()) },
        }
    }

    pub fn ptr(&self) -> xmlSecEncCtxPtr {
        self.ptr
    }
}

impl Drop for XmlSecEncCtx {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            unsafe { xmlSecEncCtxDestroy(self.ptr) }
        }
    }
}
