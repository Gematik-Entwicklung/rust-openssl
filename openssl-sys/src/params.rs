use libc::*;

#[repr(C)]
pub struct ossl_param_st {
    key: *const c_char,
    data_type: c_uint,
    data: *mut c_void,
    data_size: size_t,
    return_size: size_t,
}

pub type OSSL_PARAM = ossl_param_st;

extern "C" {
    pub fn OSSL_PARAM_construct_int(key: *const c_char, buf: *mut c_int) -> OSSL_PARAM;
    pub fn OSSL_PARAM_construct_uint(key: *const c_char, buf: *mut c_uint) -> OSSL_PARAM;
    pub fn OSSL_PARAM_construct_long(key: *const c_char, buf: *mut c_long) -> OSSL_PARAM;
    pub fn OSSL_PARAM_construct_ulong(key: *const c_char, buf: *mut c_ulong) -> OSSL_PARAM;
    pub fn OSSL_PARAM_construct_int32(key: *const c_char, buf: *mut int32_t) -> OSSL_PARAM;
    pub fn OSSL_PARAM_construct_uint32(key: *const c_char, buf: *mut uint32_t) -> OSSL_PARAM;
    pub fn OSSL_PARAM_construct_int64(key: *const c_char, buf: *mut int64_t) -> OSSL_PARAM;
    pub fn OSSL_PARAM_construct_uint64(key: *const c_char, buf: *mut uint64_t) -> OSSL_PARAM;
    pub fn OSSL_PARAM_construct_size_t(key: *const c_char, buf: *mut size_t) -> OSSL_PARAM;
    pub fn OSSL_PARAM_construct_time_t(key: *const c_char, buf: *mut time_t) -> OSSL_PARAM;
    pub fn OSSL_PARAM_construct_BN(
        key: *const c_char,
        buf: *mut c_uchar,
        bsize: size_t,
    ) -> OSSL_PARAM;
    pub fn OSSL_PARAM_construct_double(key: *const c_char, buf: *mut c_double) -> OSSL_PARAM;
    pub fn OSSL_PARAM_construct_utf8_string(
        key: *const c_char,
        buf: *mut c_char,
        bsize: size_t,
    ) -> OSSL_PARAM;
    pub fn OSSL_PARAM_construct_utf8_ptr(
        key: *const c_char,
        buf: *mut *mut c_char,
        bsize: size_t,
    ) -> OSSL_PARAM;
    pub fn OSSL_PARAM_construct_octet_string(
        key: *const c_char,
        buf: *mut c_void,
        bsize: size_t,
    ) -> OSSL_PARAM;
    pub fn OSSL_PARAM_construct_octet_ptr(
        key: *const c_char,
        buf: *mut *mut c_void,
        bsize: size_t,
    ) -> OSSL_PARAM;
    pub fn OSSL_PARAM_construct_end() -> OSSL_PARAM;
}
