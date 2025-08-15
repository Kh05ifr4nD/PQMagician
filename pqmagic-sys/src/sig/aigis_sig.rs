pub const AIGIS_SIG1_PUBLICKEYBYTES: usize = 1056;
pub const AIGIS_SIG1_SECRETKEYBYTES: usize = 2448;
pub const AIGIS_SIG1_SIGBYTES: usize = 1852;
pub const AIGIS_SIG2_PUBLICKEYBYTES: usize = 1312;
pub const AIGIS_SIG2_SECRETKEYBYTES: usize = 3376;
pub const AIGIS_SIG2_SIGBYTES: usize = 2445;
pub const AIGIS_SIG3_PUBLICKEYBYTES: usize = 1568;
pub const AIGIS_SIG3_SECRETKEYBYTES: usize = 3888;
pub const AIGIS_SIG3_SIGBYTES: usize = 3046;

unsafe extern "C" {
  pub fn pqmagic_aigis_sig1_std_keypair(
    pk: *mut ::core::ffi::c_uchar,
    sk: *mut ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_aigis_sig1_std_keypair_internal(
    pk: *mut ::core::ffi::c_uchar,
    sk: *mut ::core::ffi::c_uchar,
    keypair_coins: *mut ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_aigis_sig1_std_signature(
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
  pub fn pqmagic_aigis_sig1_std_signature_internal(
    sig: *mut ::core::ffi::c_uchar,
    siglen: *mut usize,
    m: *const ::core::ffi::c_uchar,
    mlen: usize,
    sk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_aigis_sig1_std_verify(
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
  pub fn pqmagic_aigis_sig1_std_verify_internal(
    sig: *const ::core::ffi::c_uchar,
    siglen: usize,
    m: *const ::core::ffi::c_uchar,
    mlen: usize,
    pk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_aigis_sig1_std(
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
  pub fn pqmagic_aigis_sig1_std_open(
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
  pub fn pqmagic_aigis_sig2_std_keypair(
    pk: *mut ::core::ffi::c_uchar,
    sk: *mut ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_aigis_sig2_std_keypair_internal(
    pk: *mut ::core::ffi::c_uchar,
    sk: *mut ::core::ffi::c_uchar,
    keypair_coins: *mut ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_aigis_sig2_std_signature(
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
  pub fn pqmagic_aigis_sig2_std_signature_internal(
    sig: *mut ::core::ffi::c_uchar,
    siglen: *mut usize,
    m: *const ::core::ffi::c_uchar,
    mlen: usize,
    sk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_aigis_sig2_std_verify(
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
  pub fn pqmagic_aigis_sig2_std_verify_internal(
    sig: *const ::core::ffi::c_uchar,
    siglen: usize,
    m: *const ::core::ffi::c_uchar,
    mlen: usize,
    pk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_aigis_sig2_std(
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
  pub fn pqmagic_aigis_sig2_std_open(
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
  pub fn pqmagic_aigis_sig3_std_keypair(
    pk: *mut ::core::ffi::c_uchar,
    sk: *mut ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_aigis_sig3_std_keypair_internal(
    pk: *mut ::core::ffi::c_uchar,
    sk: *mut ::core::ffi::c_uchar,
    keypair_coins: *mut ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_aigis_sig3_std_signature(
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
  pub fn pqmagic_aigis_sig3_std_signature_internal(
    sig: *mut ::core::ffi::c_uchar,
    siglen: *mut usize,
    m: *const ::core::ffi::c_uchar,
    mlen: usize,
    sk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_aigis_sig3_std_verify(
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
  pub fn pqmagic_aigis_sig3_std_verify_internal(
    sig: *const ::core::ffi::c_uchar,
    siglen: usize,
    m: *const ::core::ffi::c_uchar,
    mlen: usize,
    pk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_aigis_sig3_std(
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
  pub fn pqmagic_aigis_sig3_std_open(
    m: *mut ::core::ffi::c_uchar,
    mlen: *mut usize,
    sm: *const ::core::ffi::c_uchar,
    smlen: usize,
    ctx: *const ::core::ffi::c_uchar,
    ctx_len: usize,
    pk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
