pub const ML_DSA_44_PUBLICKEYBYTES: usize = 1312;
pub const ML_DSA_44_SECRETKEYBYTES: usize = 2560;
pub const ML_DSA_44_SIGBYTES: usize = 2420;
pub const ML_DSA_65_PUBLICKEYBYTES: usize = 1952;
pub const ML_DSA_65_SECRETKEYBYTES: usize = 4032;
pub const ML_DSA_65_SIGBYTES: usize = 3309;
pub const ML_DSA_87_PUBLICKEYBYTES: usize = 2592;
pub const ML_DSA_87_SECRETKEYBYTES: usize = 4896;
pub const ML_DSA_87_SIGBYTES: usize = 4627;

unsafe extern "C" {
  pub fn pqmagic_ml_dsa_44_std_keypair(
    pk: *mut ::core::ffi::c_uchar,
    sk: *mut ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_ml_dsa_44_std_keypair_internal(
    pk: *mut ::core::ffi::c_uchar,
    sk: *mut ::core::ffi::c_uchar,
    keypair_coins: *mut ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_ml_dsa_44_std_signature(
    sig: *mut ::core::ffi::c_uchar,
    siglen: *mut usize,
    m: *const ::core::ffi::c_uchar,
    mlen: usize,
    ctx: *const ::core::ffi::c_uchar,
    ctx_len: usize,
    sk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_ml_dsa_44_std_signature_internal(
    sig: *mut ::core::ffi::c_uchar,
    siglen: *mut usize,
    m: *const ::core::ffi::c_uchar,
    mlen: usize,
    sign_coins: *mut ::core::ffi::c_uchar,
    sk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_ml_dsa_44_std_verify(
    sig: *const ::core::ffi::c_uchar,
    siglen: usize,
    m: *const ::core::ffi::c_uchar,
    mlen: usize,
    ctx: *const ::core::ffi::c_uchar,
    ctx_len: usize,
    pk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_ml_dsa_44_std_verify_internal(
    sig: *const ::core::ffi::c_uchar,
    siglen: usize,
    m: *const ::core::ffi::c_uchar,
    mlen: usize,
    pk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_ml_dsa_44_std(
    sm: *mut ::core::ffi::c_uchar,
    smlen: *mut usize,
    m: *const ::core::ffi::c_uchar,
    mlen: usize,
    ctx: *const ::core::ffi::c_uchar,
    ctx_len: usize,
    sk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_ml_dsa_44_std_open(
    m: *mut ::core::ffi::c_uchar,
    mlen: *mut usize,
    sm: *const ::core::ffi::c_uchar,
    smlen: usize,
    ctx: *const ::core::ffi::c_uchar,
    ctx_len: usize,
    pk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_ml_dsa_65_std_keypair(
    pk: *mut ::core::ffi::c_uchar,
    sk: *mut ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_ml_dsa_65_std_keypair_internal(
    pk: *mut ::core::ffi::c_uchar,
    sk: *mut ::core::ffi::c_uchar,
    keypair_coins: *mut ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_ml_dsa_65_std_signature(
    sig: *mut ::core::ffi::c_uchar,
    siglen: *mut usize,
    m: *const ::core::ffi::c_uchar,
    mlen: usize,
    ctx: *const ::core::ffi::c_uchar,
    ctx_len: usize,
    sk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_ml_dsa_65_std_signature_internal(
    sig: *mut ::core::ffi::c_uchar,
    siglen: *mut usize,
    m: *const ::core::ffi::c_uchar,
    mlen: usize,
    sign_coins: *mut ::core::ffi::c_uchar,
    sk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_ml_dsa_65_std_verify(
    sig: *const ::core::ffi::c_uchar,
    siglen: usize,
    m: *const ::core::ffi::c_uchar,
    mlen: usize,
    ctx: *const ::core::ffi::c_uchar,
    ctx_len: usize,
    pk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_ml_dsa_65_std_verify_internal(
    sig: *const ::core::ffi::c_uchar,
    siglen: usize,
    m: *const ::core::ffi::c_uchar,
    mlen: usize,
    pk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_ml_dsa_65_std(
    sm: *mut ::core::ffi::c_uchar,
    smlen: *mut usize,
    m: *const ::core::ffi::c_uchar,
    mlen: usize,
    ctx: *const ::core::ffi::c_uchar,
    ctx_len: usize,
    sk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_ml_dsa_65_std_open(
    m: *mut ::core::ffi::c_uchar,
    mlen: *mut usize,
    sm: *const ::core::ffi::c_uchar,
    smlen: usize,
    ctx: *const ::core::ffi::c_uchar,
    ctx_len: usize,
    pk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_ml_dsa_87_std_keypair(
    pk: *mut ::core::ffi::c_uchar,
    sk: *mut ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_ml_dsa_87_std_keypair_internal(
    pk: *mut ::core::ffi::c_uchar,
    sk: *mut ::core::ffi::c_uchar,
    keypair_coins: *mut ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_ml_dsa_87_std_signature(
    sig: *mut ::core::ffi::c_uchar,
    siglen: *mut usize,
    m: *const ::core::ffi::c_uchar,
    mlen: usize,
    ctx: *const ::core::ffi::c_uchar,
    ctx_len: usize,
    sk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_ml_dsa_87_std_signature_internal(
    sig: *mut ::core::ffi::c_uchar,
    siglen: *mut usize,
    m: *const ::core::ffi::c_uchar,
    mlen: usize,
    sign_coins: *mut ::core::ffi::c_uchar,
    sk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_ml_dsa_87_std_verify(
    sig: *const ::core::ffi::c_uchar,
    siglen: usize,
    m: *const ::core::ffi::c_uchar,
    mlen: usize,
    ctx: *const ::core::ffi::c_uchar,
    ctx_len: usize,
    pk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_ml_dsa_87_std_verify_internal(
    sig: *const ::core::ffi::c_uchar,
    siglen: usize,
    m: *const ::core::ffi::c_uchar,
    mlen: usize,
    pk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_ml_dsa_87_std(
    sm: *mut ::core::ffi::c_uchar,
    smlen: *mut usize,
    m: *const ::core::ffi::c_uchar,
    mlen: usize,
    ctx: *const ::core::ffi::c_uchar,
    ctx_len: usize,
    sk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_ml_dsa_87_std_open(
    m: *mut ::core::ffi::c_uchar,
    mlen: *mut usize,
    sm: *const ::core::ffi::c_uchar,
    smlen: usize,
    ctx: *const ::core::ffi::c_uchar,
    ctx_len: usize,
    pk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
