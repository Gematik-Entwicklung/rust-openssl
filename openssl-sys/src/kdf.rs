use crate::*;
use libc::*;

pub enum EVP_KDF {}
pub enum EVP_KDF_CTX {}
pub enum OSSL_LIB_CTX {}

extern "C" {
    pub fn EVP_KDF_fetch(
        libctx: *mut OSSL_LIB_CTX,
        algorithm: *const c_char,
        properties: *const c_char,
    ) -> *mut EVP_KDF;
    pub fn EVP_KDF_free(kdf: *mut EVP_KDF) -> c_void;

    pub fn EVP_KDF_CTX_new(kdf: *mut EVP_KDF) -> *mut EVP_KDF_CTX;
    pub fn EVP_KDF_CTX_free(ctx: *mut EVP_KDF_CTX) -> c_void;

    pub fn EVP_KDF_derive(
        ctx: *mut EVP_KDF_CTX,
        key: *mut c_uchar,
        keylen: size_t,
        params: *const OSSL_PARAM,
    ) -> c_int;
    pub fn EVP_KDF_CTX_set_params(ctx: *mut EVP_KDF_CTX, params: *const OSSL_PARAM) -> c_int;
}
