pub const SLH_DSA_SHA2_128f_PUBLICKEYBYTES: usize = 32;
pub const SLH_DSA_SHA2_128f_SECRETKEYBYTES: usize = 64;
pub const SLH_DSA_SHA2_128f_SIGBYTES: usize = 17088;
pub const SLH_DSA_SHA2_128s_PUBLICKEYBYTES: usize = 32;
pub const SLH_DSA_SHA2_128s_SECRETKEYBYTES: usize = 64;
pub const SLH_DSA_SHA2_128s_SIGBYTES: usize = 7856;
pub const SLH_DSA_SHA2_192f_PUBLICKEYBYTES: usize = 48;
pub const SLH_DSA_SHA2_192f_SECRETKEYBYTES: usize = 96;
pub const SLH_DSA_SHA2_192f_SIGBYTES: usize = 35664;
pub const SLH_DSA_SHA2_192s_PUBLICKEYBYTES: usize = 48;
pub const SLH_DSA_SHA2_192s_SECRETKEYBYTES: usize = 96;
pub const SLH_DSA_SHA2_192s_SIGBYTES: usize = 16224;
pub const SLH_DSA_SHA2_256f_PUBLICKEYBYTES: usize = 64;
pub const SLH_DSA_SHA2_256f_SECRETKEYBYTES: usize = 128;
pub const SLH_DSA_SHA2_256f_SIGBYTES: usize = 49856;
pub const SLH_DSA_SHA2_256s_PUBLICKEYBYTES: usize = 64;
pub const SLH_DSA_SHA2_256s_SECRETKEYBYTES: usize = 128;
pub const SLH_DSA_SHA2_256s_SIGBYTES: usize = 29792;
pub const SLH_DSA_SHAKE_128f_PUBLICKEYBYTES: usize = 32;
pub const SLH_DSA_SHAKE_128f_SECRETKEYBYTES: usize = 64;
pub const SLH_DSA_SHAKE_128f_SIGBYTES: usize = 17088;
pub const SLH_DSA_SHAKE_128s_PUBLICKEYBYTES: usize = 32;
pub const SLH_DSA_SHAKE_128s_SECRETKEYBYTES: usize = 64;
pub const SLH_DSA_SHAKE_128s_SIGBYTES: usize = 7856;
pub const SLH_DSA_SHAKE_192f_PUBLICKEYBYTES: usize = 48;
pub const SLH_DSA_SHAKE_192f_SECRETKEYBYTES: usize = 96;
pub const SLH_DSA_SHAKE_192f_SIGBYTES: usize = 35664;
pub const SLH_DSA_SHAKE_192s_PUBLICKEYBYTES: usize = 48;
pub const SLH_DSA_SHAKE_192s_SECRETKEYBYTES: usize = 96;
pub const SLH_DSA_SHAKE_192s_SIGBYTES: usize = 16224;
pub const SLH_DSA_SHAKE_256f_PUBLICKEYBYTES: usize = 64;
pub const SLH_DSA_SHAKE_256f_SECRETKEYBYTES: usize = 128;
pub const SLH_DSA_SHAKE_256f_SIGBYTES: usize = 49856;
pub const SLH_DSA_SHAKE_256s_PUBLICKEYBYTES: usize = 64;
pub const SLH_DSA_SHAKE_256s_SECRETKEYBYTES: usize = 128;
pub const SLH_DSA_SHAKE_256s_SIGBYTES: usize = 29792;
pub const SLH_DSA_SM3_128f_PUBLICKEYBYTES: usize = 32;
pub const SLH_DSA_SM3_128f_SECRETKEYBYTES: usize = 64;
pub const SLH_DSA_SM3_128f_SIGBYTES: usize = 17088;
pub const SLH_DSA_SM3_128s_PUBLICKEYBYTES: usize = 32;
pub const SLH_DSA_SM3_128s_SECRETKEYBYTES: usize = 64;
pub const SLH_DSA_SM3_128s_SIGBYTES: usize = 7856;

unsafe extern "C" {
  pub fn pqmagic_slh_dsa_sha2_128f_simple_std_sign_keypair(
    pk: *mut ::core::ffi::c_uchar,
    sk: *mut ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_slh_dsa_sha2_128f_simple_std_sign_signature(
    sm: *mut ::core::ffi::c_uchar,
    smlen: *mut usize,
    m: *const ::core::ffi::c_uchar,
    mlen: usize,
    sk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_slh_dsa_sha2_128f_simple_std_sign_verify(
    sm: *const ::core::ffi::c_uchar,
    smlen: usize,
    m: *const ::core::ffi::c_uchar,
    mlen: usize,
    pk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_slh_dsa_sha2_128f_simple_std_sign(
    sm: *mut ::core::ffi::c_uchar,
    smlen: *mut usize,
    m: *const ::core::ffi::c_uchar,
    mlen: usize,
    sk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_slh_dsa_sha2_128f_simple_std_sign_open(
    m: *mut ::core::ffi::c_uchar,
    mlen: *mut usize,
    sm: *const ::core::ffi::c_uchar,
    smlen: usize,
    pk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_slh_dsa_sha2_128s_simple_std_sign_keypair(
    pk: *mut ::core::ffi::c_uchar,
    sk: *mut ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_slh_dsa_sha2_128s_simple_std_sign_signature(
    sm: *mut ::core::ffi::c_uchar,
    smlen: *mut usize,
    m: *const ::core::ffi::c_uchar,
    mlen: usize,
    sk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_slh_dsa_sha2_128s_simple_std_sign_verify(
    sm: *const ::core::ffi::c_uchar,
    smlen: usize,
    m: *const ::core::ffi::c_uchar,
    mlen: usize,
    pk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_slh_dsa_sha2_128s_simple_std_sign(
    sm: *mut ::core::ffi::c_uchar,
    smlen: *mut usize,
    m: *const ::core::ffi::c_uchar,
    mlen: usize,
    sk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_slh_dsa_sha2_128s_simple_std_sign_open(
    m: *mut ::core::ffi::c_uchar,
    mlen: *mut usize,
    sm: *const ::core::ffi::c_uchar,
    smlen: usize,
    pk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_slh_dsa_sha2_192f_simple_std_sign_keypair(
    pk: *mut ::core::ffi::c_uchar,
    sk: *mut ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_slh_dsa_sha2_192f_simple_std_sign_signature(
    sm: *mut ::core::ffi::c_uchar,
    smlen: *mut usize,
    m: *const ::core::ffi::c_uchar,
    mlen: usize,
    sk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_slh_dsa_sha2_192f_simple_std_sign_verify(
    sm: *const ::core::ffi::c_uchar,
    smlen: usize,
    m: *const ::core::ffi::c_uchar,
    mlen: usize,
    pk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_slh_dsa_sha2_192f_simple_std_sign(
    sm: *mut ::core::ffi::c_uchar,
    smlen: *mut usize,
    m: *const ::core::ffi::c_uchar,
    mlen: usize,
    sk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_slh_dsa_sha2_192f_simple_std_sign_open(
    m: *mut ::core::ffi::c_uchar,
    mlen: *mut usize,
    sm: *const ::core::ffi::c_uchar,
    smlen: usize,
    pk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_slh_dsa_sha2_192s_simple_std_sign_keypair(
    pk: *mut ::core::ffi::c_uchar,
    sk: *mut ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_slh_dsa_sha2_192s_simple_std_sign_signature(
    sm: *mut ::core::ffi::c_uchar,
    smlen: *mut usize,
    m: *const ::core::ffi::c_uchar,
    mlen: usize,
    sk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_slh_dsa_sha2_192s_simple_std_sign_verify(
    sm: *const ::core::ffi::c_uchar,
    smlen: usize,
    m: *const ::core::ffi::c_uchar,
    mlen: usize,
    pk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_slh_dsa_sha2_192s_simple_std_sign(
    sm: *mut ::core::ffi::c_uchar,
    smlen: *mut usize,
    m: *const ::core::ffi::c_uchar,
    mlen: usize,
    sk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_slh_dsa_sha2_192s_simple_std_sign_open(
    m: *mut ::core::ffi::c_uchar,
    mlen: *mut usize,
    sm: *const ::core::ffi::c_uchar,
    smlen: usize,
    pk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_slh_dsa_sha2_256f_simple_std_sign_keypair(
    pk: *mut ::core::ffi::c_uchar,
    sk: *mut ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_slh_dsa_sha2_256f_simple_std_sign_signature(
    sm: *mut ::core::ffi::c_uchar,
    smlen: *mut usize,
    m: *const ::core::ffi::c_uchar,
    mlen: usize,
    sk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_slh_dsa_sha2_256f_simple_std_sign_verify(
    sm: *const ::core::ffi::c_uchar,
    smlen: usize,
    m: *const ::core::ffi::c_uchar,
    mlen: usize,
    pk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_slh_dsa_sha2_256f_simple_std_sign(
    sm: *mut ::core::ffi::c_uchar,
    smlen: *mut usize,
    m: *const ::core::ffi::c_uchar,
    mlen: usize,
    sk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_slh_dsa_sha2_256f_simple_std_sign_open(
    m: *mut ::core::ffi::c_uchar,
    mlen: *mut usize,
    sm: *const ::core::ffi::c_uchar,
    smlen: usize,
    pk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_slh_dsa_sha2_256s_simple_std_sign_keypair(
    pk: *mut ::core::ffi::c_uchar,
    sk: *mut ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_slh_dsa_sha2_256s_simple_std_sign_signature(
    sm: *mut ::core::ffi::c_uchar,
    smlen: *mut usize,
    m: *const ::core::ffi::c_uchar,
    mlen: usize,
    sk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_slh_dsa_sha2_256s_simple_std_sign_verify(
    sm: *const ::core::ffi::c_uchar,
    smlen: usize,
    m: *const ::core::ffi::c_uchar,
    mlen: usize,
    pk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_slh_dsa_sha2_256s_simple_std_sign(
    sm: *mut ::core::ffi::c_uchar,
    smlen: *mut usize,
    m: *const ::core::ffi::c_uchar,
    mlen: usize,
    sk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_slh_dsa_sha2_256s_simple_std_sign_open(
    m: *mut ::core::ffi::c_uchar,
    mlen: *mut usize,
    sm: *const ::core::ffi::c_uchar,
    smlen: usize,
    pk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_slh_dsa_shake_128f_simple_std_sign_keypair(
    pk: *mut ::core::ffi::c_uchar,
    sk: *mut ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_slh_dsa_shake_128f_simple_std_sign_signature(
    sm: *mut ::core::ffi::c_uchar,
    smlen: *mut usize,
    m: *const ::core::ffi::c_uchar,
    mlen: usize,
    sk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_slh_dsa_shake_128f_simple_std_sign_verify(
    sm: *const ::core::ffi::c_uchar,
    smlen: usize,
    m: *const ::core::ffi::c_uchar,
    mlen: usize,
    pk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_slh_dsa_shake_128f_simple_std_sign(
    sm: *mut ::core::ffi::c_uchar,
    smlen: *mut usize,
    m: *const ::core::ffi::c_uchar,
    mlen: usize,
    sk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_slh_dsa_shake_128f_simple_std_sign_open(
    m: *mut ::core::ffi::c_uchar,
    mlen: *mut usize,
    sm: *const ::core::ffi::c_uchar,
    smlen: usize,
    pk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_slh_dsa_shake_128s_simple_std_sign_keypair(
    pk: *mut ::core::ffi::c_uchar,
    sk: *mut ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_slh_dsa_shake_128s_simple_std_sign_signature(
    sm: *mut ::core::ffi::c_uchar,
    smlen: *mut usize,
    m: *const ::core::ffi::c_uchar,
    mlen: usize,
    sk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_slh_dsa_shake_128s_simple_std_sign_verify(
    sm: *const ::core::ffi::c_uchar,
    smlen: usize,
    m: *const ::core::ffi::c_uchar,
    mlen: usize,
    pk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_slh_dsa_shake_128s_simple_std_sign(
    sm: *mut ::core::ffi::c_uchar,
    smlen: *mut usize,
    m: *const ::core::ffi::c_uchar,
    mlen: usize,
    sk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_slh_dsa_shake_128s_simple_std_sign_open(
    m: *mut ::core::ffi::c_uchar,
    mlen: *mut usize,
    sm: *const ::core::ffi::c_uchar,
    smlen: usize,
    pk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_slh_dsa_shake_192f_simple_std_sign_keypair(
    pk: *mut ::core::ffi::c_uchar,
    sk: *mut ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_slh_dsa_shake_192f_simple_std_sign_signature(
    sm: *mut ::core::ffi::c_uchar,
    smlen: *mut usize,
    m: *const ::core::ffi::c_uchar,
    mlen: usize,
    sk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_slh_dsa_shake_192f_simple_std_sign_verify(
    sm: *const ::core::ffi::c_uchar,
    smlen: usize,
    m: *const ::core::ffi::c_uchar,
    mlen: usize,
    pk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_slh_dsa_shake_192f_simple_std_sign(
    sm: *mut ::core::ffi::c_uchar,
    smlen: *mut usize,
    m: *const ::core::ffi::c_uchar,
    mlen: usize,
    sk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_slh_dsa_shake_192f_simple_std_sign_open(
    m: *mut ::core::ffi::c_uchar,
    mlen: *mut usize,
    sm: *const ::core::ffi::c_uchar,
    smlen: usize,
    pk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_slh_dsa_shake_192s_simple_std_sign_keypair(
    pk: *mut ::core::ffi::c_uchar,
    sk: *mut ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_slh_dsa_shake_192s_simple_std_sign_signature(
    sm: *mut ::core::ffi::c_uchar,
    smlen: *mut usize,
    m: *const ::core::ffi::c_uchar,
    mlen: usize,
    sk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_slh_dsa_shake_192s_simple_std_sign_verify(
    sm: *const ::core::ffi::c_uchar,
    smlen: usize,
    m: *const ::core::ffi::c_uchar,
    mlen: usize,
    pk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_slh_dsa_shake_192s_simple_std_sign(
    sm: *mut ::core::ffi::c_uchar,
    smlen: *mut usize,
    m: *const ::core::ffi::c_uchar,
    mlen: usize,
    sk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_slh_dsa_shake_192s_simple_std_sign_open(
    m: *mut ::core::ffi::c_uchar,
    mlen: *mut usize,
    sm: *const ::core::ffi::c_uchar,
    smlen: usize,
    pk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_slh_dsa_shake_256f_simple_std_sign_keypair(
    pk: *mut ::core::ffi::c_uchar,
    sk: *mut ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_slh_dsa_shake_256f_simple_std_sign_signature(
    sm: *mut ::core::ffi::c_uchar,
    smlen: *mut usize,
    m: *const ::core::ffi::c_uchar,
    mlen: usize,
    sk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_slh_dsa_shake_256f_simple_std_sign_verify(
    sm: *const ::core::ffi::c_uchar,
    smlen: usize,
    m: *const ::core::ffi::c_uchar,
    mlen: usize,
    pk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_slh_dsa_shake_256f_simple_std_sign(
    sm: *mut ::core::ffi::c_uchar,
    smlen: *mut usize,
    m: *const ::core::ffi::c_uchar,
    mlen: usize,
    sk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_slh_dsa_shake_256f_simple_std_sign_open(
    m: *mut ::core::ffi::c_uchar,
    mlen: *mut usize,
    sm: *const ::core::ffi::c_uchar,
    smlen: usize,
    pk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_slh_dsa_shake_256s_simple_std_sign_keypair(
    pk: *mut ::core::ffi::c_uchar,
    sk: *mut ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_slh_dsa_shake_256s_simple_std_sign_signature(
    sm: *mut ::core::ffi::c_uchar,
    smlen: *mut usize,
    m: *const ::core::ffi::c_uchar,
    mlen: usize,
    sk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_slh_dsa_shake_256s_simple_std_sign_verify(
    sm: *const ::core::ffi::c_uchar,
    smlen: usize,
    m: *const ::core::ffi::c_uchar,
    mlen: usize,
    pk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_slh_dsa_shake_256s_simple_std_sign(
    sm: *mut ::core::ffi::c_uchar,
    smlen: *mut usize,
    m: *const ::core::ffi::c_uchar,
    mlen: usize,
    sk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_slh_dsa_shake_256s_simple_std_sign_open(
    m: *mut ::core::ffi::c_uchar,
    mlen: *mut usize,
    sm: *const ::core::ffi::c_uchar,
    smlen: usize,
    pk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_slh_dsa_sm3_128f_simple_std_sign_keypair(
    pk: *mut ::core::ffi::c_uchar,
    sk: *mut ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_slh_dsa_sm3_128f_simple_std_sign_signature(
    sm: *mut ::core::ffi::c_uchar,
    smlen: *mut usize,
    m: *const ::core::ffi::c_uchar,
    mlen: usize,
    sk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_slh_dsa_sm3_128f_simple_std_sign_verify(
    sm: *const ::core::ffi::c_uchar,
    smlen: usize,
    m: *const ::core::ffi::c_uchar,
    mlen: usize,
    pk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_slh_dsa_sm3_128f_simple_std_sign(
    sm: *mut ::core::ffi::c_uchar,
    smlen: *mut usize,
    m: *const ::core::ffi::c_uchar,
    mlen: usize,
    sk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_slh_dsa_sm3_128f_simple_std_sign_open(
    m: *mut ::core::ffi::c_uchar,
    mlen: *mut usize,
    sm: *const ::core::ffi::c_uchar,
    smlen: usize,
    pk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_slh_dsa_sm3_128s_simple_std_sign_keypair(
    pk: *mut ::core::ffi::c_uchar,
    sk: *mut ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_slh_dsa_sm3_128s_simple_std_sign_signature(
    sm: *mut ::core::ffi::c_uchar,
    smlen: *mut usize,
    m: *const ::core::ffi::c_uchar,
    mlen: usize,
    sk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_slh_dsa_sm3_128s_simple_std_sign_verify(
    sm: *const ::core::ffi::c_uchar,
    smlen: usize,
    m: *const ::core::ffi::c_uchar,
    mlen: usize,
    pk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_slh_dsa_sm3_128s_simple_std_sign(
    sm: *mut ::core::ffi::c_uchar,
    smlen: *mut usize,
    m: *const ::core::ffi::c_uchar,
    mlen: usize,
    sk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_slh_dsa_sm3_128s_simple_std_sign_open(
    m: *mut ::core::ffi::c_uchar,
    mlen: *mut usize,
    sm: *const ::core::ffi::c_uchar,
    smlen: usize,
    pk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
