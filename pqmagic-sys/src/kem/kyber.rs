pub const KYBER512_PUBLICKEYBYTES: usize = 800;
pub const KYBER512_SECRETKEYBYTES: usize = 1632;
pub const KYBER512_CIPHERTEXTBYTES: usize = 768;
pub const KYBER512_SSBYTES: usize = 32;
pub const KYBER768_PUBLICKEYBYTES: usize = 1184;
pub const KYBER768_SECRETKEYBYTES: usize = 2400;
pub const KYBER768_CIPHERTEXTBYTES: usize = 1088;
pub const KYBER768_SSBYTES: usize = 32;
pub const KYBER1024_PUBLICKEYBYTES: usize = 1568;
pub const KYBER1024_SECRETKEYBYTES: usize = 3168;
pub const KYBER1024_CIPHERTEXTBYTES: usize = 1568;
pub const KYBER1024_SSBYTES: usize = 32;

unsafe extern "C" {
  pub fn pqmagic_kyber512_std_keypair(
    pk: *mut ::core::ffi::c_uchar,
    sk: *mut ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_kyber512_std_keypair_internal(
    pk: *mut ::core::ffi::c_uchar,
    sk: *mut ::core::ffi::c_uchar,
    keypair_coins: *mut ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_kyber512_std_enc(
    ct: *mut ::core::ffi::c_uchar,
    ss: *mut ::core::ffi::c_uchar,
    pk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_kyber512_std_enc_internal(
    ct: *mut ::core::ffi::c_uchar,
    ss: *mut ::core::ffi::c_uchar,
    pk: *const ::core::ffi::c_uchar,
    kem_enc_coins: *mut ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_kyber512_std_dec(
    ss: *mut ::core::ffi::c_uchar,
    ct: *const ::core::ffi::c_uchar,
    sk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_kyber768_std_keypair(
    pk: *mut ::core::ffi::c_uchar,
    sk: *mut ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_kyber768_std_keypair_internal(
    pk: *mut ::core::ffi::c_uchar,
    sk: *mut ::core::ffi::c_uchar,
    keypair_coins: *mut ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_kyber768_std_enc(
    ct: *mut ::core::ffi::c_uchar,
    ss: *mut ::core::ffi::c_uchar,
    pk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_kyber768_std_enc_internal(
    ct: *mut ::core::ffi::c_uchar,
    ss: *mut ::core::ffi::c_uchar,
    pk: *const ::core::ffi::c_uchar,
    kem_enc_coins: *mut ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_kyber768_std_dec(
    ss: *mut ::core::ffi::c_uchar,
    ct: *const ::core::ffi::c_uchar,
    sk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_kyber1024_std_keypair(
    pk: *mut ::core::ffi::c_uchar,
    sk: *mut ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_kyber1024_std_keypair_internal(
    pk: *mut ::core::ffi::c_uchar,
    sk: *mut ::core::ffi::c_uchar,
    keypair_coins: *mut ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_kyber1024_std_enc(
    ct: *mut ::core::ffi::c_uchar,
    ss: *mut ::core::ffi::c_uchar,
    pk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_kyber1024_std_enc_internal(
    ct: *mut ::core::ffi::c_uchar,
    ss: *mut ::core::ffi::c_uchar,
    pk: *const ::core::ffi::c_uchar,
    kem_enc_coins: *mut ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_kyber1024_std_dec(
    ss: *mut ::core::ffi::c_uchar,
    ct: *const ::core::ffi::c_uchar,
    sk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
