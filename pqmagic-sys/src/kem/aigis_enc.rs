pub const AIGIS_ENC_1_PUBLICKEYBYTES: usize = 672;
pub const AIGIS_ENC_1_SECRETKEYBYTES: usize = 1568;
pub const AIGIS_ENC_1_CIPHERTEXTBYTES: usize = 736;
pub const AIGIS_ENC_1_SSBYTES: usize = 32;
pub const AIGIS_ENC_2_PUBLICKEYBYTES: usize = 896;
pub const AIGIS_ENC_2_SECRETKEYBYTES: usize = 2208;
pub const AIGIS_ENC_2_CIPHERTEXTBYTES: usize = 992;
pub const AIGIS_ENC_2_SSBYTES: usize = 32;
pub const AIGIS_ENC_3_PUBLICKEYBYTES: usize = 992;
pub const AIGIS_ENC_3_SECRETKEYBYTES: usize = 2304;
pub const AIGIS_ENC_3_CIPHERTEXTBYTES: usize = 1056;
pub const AIGIS_ENC_3_SSBYTES: usize = 32;
pub const AIGIS_ENC_4_PUBLICKEYBYTES: usize = 1440;
pub const AIGIS_ENC_4_SECRETKEYBYTES: usize = 3168;
pub const AIGIS_ENC_4_CIPHERTEXTBYTES: usize = 1568;
pub const AIGIS_ENC_4_SSBYTES: usize = 32;

unsafe extern "C" {
  pub fn pqmagic_aigis_enc_1_std_keypair(
    pk: *mut ::core::ffi::c_uchar,
    sk: *mut ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_aigis_enc_1_std_keypair_internal(
    pk: *mut ::core::ffi::c_uchar,
    sk: *mut ::core::ffi::c_uchar,
    keypair_coins: *mut ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_aigis_enc_1_std_enc(
    ct: *mut ::core::ffi::c_uchar,
    ss: *mut ::core::ffi::c_uchar,
    pk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_aigis_enc_1_std_enc_internal(
    ct: *mut ::core::ffi::c_uchar,
    ss: *mut ::core::ffi::c_uchar,
    pk: *const ::core::ffi::c_uchar,
    kem_enc_coins: *mut ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_aigis_enc_1_std_dec(
    ss: *mut ::core::ffi::c_uchar,
    ct: *const ::core::ffi::c_uchar,
    sk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_aigis_enc_2_std_keypair(
    pk: *mut ::core::ffi::c_uchar,
    sk: *mut ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_aigis_enc_2_std_keypair_internal(
    pk: *mut ::core::ffi::c_uchar,
    sk: *mut ::core::ffi::c_uchar,
    keypair_coins: *mut ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_aigis_enc_2_std_enc(
    ct: *mut ::core::ffi::c_uchar,
    ss: *mut ::core::ffi::c_uchar,
    pk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_aigis_enc_2_std_enc_internal(
    ct: *mut ::core::ffi::c_uchar,
    ss: *mut ::core::ffi::c_uchar,
    pk: *const ::core::ffi::c_uchar,
    kem_enc_coins: *mut ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_aigis_enc_2_std_dec(
    ss: *mut ::core::ffi::c_uchar,
    ct: *const ::core::ffi::c_uchar,
    sk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_aigis_enc_3_std_keypair(
    pk: *mut ::core::ffi::c_uchar,
    sk: *mut ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_aigis_enc_3_std_keypair_internal(
    pk: *mut ::core::ffi::c_uchar,
    sk: *mut ::core::ffi::c_uchar,
    keypair_coins: *mut ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_aigis_enc_3_std_enc(
    ct: *mut ::core::ffi::c_uchar,
    ss: *mut ::core::ffi::c_uchar,
    pk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_aigis_enc_3_std_enc_internal(
    ct: *mut ::core::ffi::c_uchar,
    ss: *mut ::core::ffi::c_uchar,
    pk: *const ::core::ffi::c_uchar,
    kem_enc_coins: *mut ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_aigis_enc_3_std_dec(
    ss: *mut ::core::ffi::c_uchar,
    ct: *const ::core::ffi::c_uchar,
    sk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_aigis_enc_4_std_keypair(
    pk: *mut ::core::ffi::c_uchar,
    sk: *mut ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_aigis_enc_4_std_keypair_internal(
    pk: *mut ::core::ffi::c_uchar,
    sk: *mut ::core::ffi::c_uchar,
    keypair_coins: *mut ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_aigis_enc_4_std_enc(
    ct: *mut ::core::ffi::c_uchar,
    ss: *mut ::core::ffi::c_uchar,
    pk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_aigis_enc_4_std_enc_internal(
    ct: *mut ::core::ffi::c_uchar,
    ss: *mut ::core::ffi::c_uchar,
    pk: *const ::core::ffi::c_uchar,
    kem_enc_coins: *mut ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_aigis_enc_4_std_dec(
    ss: *mut ::core::ffi::c_uchar,
    ct: *const ::core::ffi::c_uchar,
    sk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
