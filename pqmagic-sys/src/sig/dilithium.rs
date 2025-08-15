pub const DILITHIUM2_PUBLICKEYBYTES: usize = 1312;
pub const DILITHIUM2_SECRETKEYBYTES: usize = 2528;
pub const DILITHIUM2_SIGBYTES: usize = 2420;
pub const DILITHIUM3_PUBLICKEYBYTES: usize = 1952;
pub const DILITHIUM3_SECRETKEYBYTES: usize = 4000;
pub const DILITHIUM3_SIGBYTES: usize = 3293;
pub const DILITHIUM5_PUBLICKEYBYTES: usize = 2592;
pub const DILITHIUM5_SECRETKEYBYTES: usize = 4864;
pub const DILITHIUM5_SIGBYTES: usize = 4595;

unsafe extern "C" {
  pub fn pqmagic_dilithium2_std_keypair(
    pk: *mut ::core::ffi::c_uchar,
    sk: *mut ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_dilithium2_std_keypair_internal(
    pk: *mut ::core::ffi::c_uchar,
    sk: *mut ::core::ffi::c_uchar,
    keypair_coins: *mut ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_dilithium2_std_signature(
    sig: *mut ::core::ffi::c_uchar,
    siglen: *mut usize,
    m: *const ::core::ffi::c_uchar,
    mlen: usize,
    sk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_dilithium2_std_signature_internal(
    sig: *mut ::core::ffi::c_uchar,
    siglen: *mut usize,
    m: *const ::core::ffi::c_uchar,
    mlen: usize,
    sign_coins: *mut ::core::ffi::c_uchar,
    sk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_dilithium2_std_verify(
    sig: *const ::core::ffi::c_uchar,
    siglen: usize,
    m: *const ::core::ffi::c_uchar,
    mlen: usize,
    pk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_dilithium2_std(
    sm: *mut ::core::ffi::c_uchar,
    smlen: *mut usize,
    m: *const ::core::ffi::c_uchar,
    mlen: usize,
    sk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_dilithium2_std_open(
    m: *mut ::core::ffi::c_uchar,
    mlen: *mut usize,
    sm: *const ::core::ffi::c_uchar,
    smlen: usize,
    pk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_dilithium3_std_keypair(
    pk: *mut ::core::ffi::c_uchar,
    sk: *mut ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_dilithium3_std_keypair_internal(
    pk: *mut ::core::ffi::c_uchar,
    sk: *mut ::core::ffi::c_uchar,
    keypair_coins: *mut ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_dilithium3_std_signature(
    sig: *mut ::core::ffi::c_uchar,
    siglen: *mut usize,
    m: *const ::core::ffi::c_uchar,
    mlen: usize,
    sk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_dilithium3_std_signature_internal(
    sig: *mut ::core::ffi::c_uchar,
    siglen: *mut usize,
    m: *const ::core::ffi::c_uchar,
    mlen: usize,
    sign_coins: *mut ::core::ffi::c_uchar,
    sk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_dilithium3_std_verify(
    sig: *const ::core::ffi::c_uchar,
    siglen: usize,
    m: *const ::core::ffi::c_uchar,
    mlen: usize,
    pk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_dilithium3_std(
    sm: *mut ::core::ffi::c_uchar,
    smlen: *mut usize,
    m: *const ::core::ffi::c_uchar,
    mlen: usize,
    sk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_dilithium3_std_open(
    m: *mut ::core::ffi::c_uchar,
    mlen: *mut usize,
    sm: *const ::core::ffi::c_uchar,
    smlen: usize,
    pk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_dilithium5_std_keypair(
    pk: *mut ::core::ffi::c_uchar,
    sk: *mut ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_dilithium5_std_keypair_internal(
    pk: *mut ::core::ffi::c_uchar,
    sk: *mut ::core::ffi::c_uchar,
    keypair_coins: *mut ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_dilithium5_std_signature(
    sig: *mut ::core::ffi::c_uchar,
    siglen: *mut usize,
    m: *const ::core::ffi::c_uchar,
    mlen: usize,
    sk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_dilithium5_std_signature_internal(
    sig: *mut ::core::ffi::c_uchar,
    siglen: *mut usize,
    m: *const ::core::ffi::c_uchar,
    mlen: usize,
    sign_coins: *mut ::core::ffi::c_uchar,
    sk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_dilithium5_std_verify(
    sig: *const ::core::ffi::c_uchar,
    siglen: usize,
    m: *const ::core::ffi::c_uchar,
    mlen: usize,
    pk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_dilithium5_std(
    sm: *mut ::core::ffi::c_uchar,
    smlen: *mut usize,
    m: *const ::core::ffi::c_uchar,
    mlen: usize,
    sk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_dilithium5_std_open(
    m: *mut ::core::ffi::c_uchar,
    mlen: *mut usize,
    sm: *const ::core::ffi::c_uchar,
    smlen: usize,
    pk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
