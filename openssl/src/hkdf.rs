use std::ffi::CString;
use std::ptr;

use libc::*;

use crate::error::ErrorStack;
use crate::{cvt, cvt_p};

#[cfg(not(ossl300))]
pub struct Hkdf(*mut ffi::EVP_PKEY_CTX);

#[cfg(ossl300)]
pub struct Hkdf {
    digest: Option<String>,
    mode: Option<Mode>,
    secret: Option<Vec<u8>>,
    salt: Option<Vec<u8>>,
    info: Option<Vec<u8>>,
}

pub enum Mode {
    ExtractAndExpand,
    ExtractOnly,
    ExpandOnly,
}

unsafe impl Send for Hkdf {}

#[cfg(not(ossl300))]
impl Hkdf {
    pub fn new() -> Result<Self, ErrorStack> {
        unsafe {
            let ret = cvt_p(ffi::EVP_PKEY_CTX_new_id(
                ffi::EVP_PKEY_HKDF,
                ptr::null_mut(),
            ))
            .map(Hkdf)
            .and_then(|ctx| cvt(ffi::EVP_PKEY_derive_init(ctx.0)).map(|_| ctx))?;

            Ok(ret)
        }
    }

    pub fn set_digest(self, name: &str) -> Result<Self, ErrorStack> {
        unsafe {
            let name = CString::new(name).unwrap();
            let digest = ffi::EVP_get_digestbyname(name.as_ptr());
            if digest.is_null() {
                return Err(ErrorStack::get());
            }

            cvt(ffi::EVP_PKEY_CTX_set_hkdf_md(self.0, digest))?;
        }

        Ok(self)
    }

    pub fn set_mode(self, mode: Mode) -> Result<Self, ErrorStack> {
        unsafe {
            cvt(ffi::EVP_PKEY_CTX_hkdf_mode(
                self.0,
                match mode {
                    Mode::ExtractAndExpand => ffi::EVP_PKEY_HKDEF_MODE_EXTRACT_AND_EXPAND,
                    Mode::ExtractOnly => ffi::EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY,
                    Mode::ExpandOnly => ffi::EVP_PKEY_HKDEF_MODE_EXPAND_ONLY,
                },
            ))?;
        }

        Ok(self)
    }

    pub fn set_secret(self, secret: &[u8]) -> Result<Self, ErrorStack> {
        unsafe {
            cvt(ffi::EVP_PKEY_CTX_set1_hkdf_key(
                self.0,
                secret.as_ptr() as *const _,
                secret.len() as c_int,
            ))?;
        }

        Ok(self)
    }

    pub fn set_salt(self, salt: Option<&[u8]>) -> Result<Self, ErrorStack> {
        let (ptr, len) = match salt {
            Some(salt) => (salt.as_ptr() as *const _, salt.len()),
            None => (ptr::null(), 0),
        };

        unsafe {
            cvt(ffi::EVP_PKEY_CTX_set1_hkdf_salt(self.0, ptr, len as c_int))?;
        }

        Ok(self)
    }

    pub fn set_info(self, info: Option<&[u8]>) -> Result<Self, ErrorStack> {
        let (ptr, len) = match info {
            Some(info) => (info.as_ptr() as *const _, info.len()),
            None => (ptr::null(), 0),
        };

        unsafe {
            cvt(ffi::EVP_PKEY_CTX_add1_hkdf_info(self.0, ptr, len as c_int))?;
        }

        Ok(self)
    }

    pub fn derive(&mut self, mut key_len: usize) -> Result<Vec<u8>, ErrorStack> {
        let mut buf = Vec::new();
        buf.resize(key_len, 0);

        unsafe {
            cvt(ffi::EVP_PKEY_derive(self.0, buf.as_mut_ptr(), &mut key_len))?;
        }

        buf.truncate(key_len);

        Ok(buf)
    }
}

#[cfg(not(ossl300))]
impl Drop for Hkdf {
    fn drop(&mut self) {
        unsafe {
            ffi::EVP_PKEY_CTX_free(self.0);
        }
    }
}

#[cfg(ossl300)]
impl Hkdf {
    pub fn new() -> Result<Self, ErrorStack> {
        Ok(Self {
            digest: None,
            mode: None,
            secret: None,
            salt: None,
            info: None,
        })
    }

    pub fn set_digest(mut self, name: &str) -> Result<Self, ErrorStack> {
        self.digest = Some(name.to_owned());

        Ok(self)
    }

    pub fn set_mode(mut self, mode: Mode) -> Result<Self, ErrorStack> {
        self.mode = Some(mode);

        Ok(self)
    }

    pub fn set_secret(mut self, secret: &[u8]) -> Result<Self, ErrorStack> {
        self.secret = Some(secret.to_owned());

        Ok(self)
    }

    pub fn set_salt(mut self, salt: Option<&[u8]>) -> Result<Self, ErrorStack> {
        self.salt = salt.map(ToOwned::to_owned);

        Ok(self)
    }

    pub fn set_info(mut self, info: Option<&[u8]>) -> Result<Self, ErrorStack> {
        self.info = info.map(ToOwned::to_owned);

        Ok(self)
    }

    pub fn derive(&mut self, key_len: usize) -> Result<Vec<u8>, ErrorStack> {
        unsafe {
            let kdf = b"hkdf\0".as_ptr() as *const i8;
            let kdf = ffi::EVP_KDF_fetch(ptr::null_mut(), kdf, ptr::null_mut());
            let kdf = cvt_p(kdf)?;

            let kctx = ffi::EVP_KDF_CTX_new(kdf);
            ffi::EVP_KDF_free(kdf);
            let kctx = cvt_p(kctx)?;

            let mut params: Vec<ffi::OSSL_PARAM> = Vec::new();
            if let Some(digest) = &self.digest {
                params.push(ffi::OSSL_PARAM_construct_utf8_string(
                    b"digest\0".as_ptr() as *mut i8,
                    digest.as_ptr() as *mut i8,
                    digest.len(),
                ));
            }
            if let Some(salt) = &self.salt {
                params.push(ffi::OSSL_PARAM_construct_octet_string(
                    b"salt\0".as_ptr() as *mut i8,
                    salt.as_ptr() as *mut c_void,
                    salt.len(),
                ));
            }
            if let Some(secret) = &self.secret {
                params.push(ffi::OSSL_PARAM_construct_octet_string(
                    b"key\0".as_ptr() as *mut i8,
                    secret.as_ptr() as *mut c_void,
                    secret.len(),
                ));
            }
            if let Some(info) = &self.info {
                params.push(ffi::OSSL_PARAM_construct_octet_string(
                    b"info\0".as_ptr() as *mut i8,
                    info.as_ptr() as *mut c_void,
                    info.len(),
                ));
            }
            params.push(ffi::OSSL_PARAM_construct_end());

            let mut buf = Vec::new();
            buf.resize(key_len, 0);

            let ret = ffi::EVP_KDF_derive(kctx, buf.as_mut_ptr(), key_len, params.as_ptr());
            ffi::EVP_KDF_CTX_free(kctx);

            if ret >= 0 {
                Ok(buf)
            } else {
                Err(ErrorStack::get())
            }
        }
    }
}
