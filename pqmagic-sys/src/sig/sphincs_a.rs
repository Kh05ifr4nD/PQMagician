pub const SPHINCS_A_SHA2_128f_PUBLICKEYBYTES: usize = 32;
pub const SPHINCS_A_SHA2_128f_SECRETKEYBYTES: usize = 64;
pub const SPHINCS_A_SHA2_128f_SIGBYTES: usize = 16720;
pub const SPHINCS_A_SHA2_128s_PUBLICKEYBYTES: usize = 32;
pub const SPHINCS_A_SHA2_128s_SECRETKEYBYTES: usize = 64;
pub const SPHINCS_A_SHA2_128s_SIGBYTES: usize = 6880;
pub const SPHINCS_A_SHA2_192f_PUBLICKEYBYTES: usize = 48;
pub const SPHINCS_A_SHA2_192f_SECRETKEYBYTES: usize = 96;
pub const SPHINCS_A_SHA2_192f_SIGBYTES: usize = 34896;
pub const SPHINCS_A_SHA2_192s_PUBLICKEYBYTES: usize = 48;
pub const SPHINCS_A_SHA2_192s_SECRETKEYBYTES: usize = 96;
pub const SPHINCS_A_SHA2_192s_SIGBYTES: usize = 14568;
pub const SPHINCS_A_SHA2_256f_PUBLICKEYBYTES: usize = 64;
pub const SPHINCS_A_SHA2_256f_SECRETKEYBYTES: usize = 128;
pub const SPHINCS_A_SHA2_256f_SIGBYTES: usize = 49312;
pub const SPHINCS_A_SHA2_256s_PUBLICKEYBYTES: usize = 64;
pub const SPHINCS_A_SHA2_256s_SECRETKEYBYTES: usize = 128;
pub const SPHINCS_A_SHA2_256s_SIGBYTES: usize = 27232;
pub const SPHINCS_A_SHAKE_128f_PUBLICKEYBYTES: usize = 32;
pub const SPHINCS_A_SHAKE_128f_SECRETKEYBYTES: usize = 64;
pub const SPHINCS_A_SHAKE_128f_SIGBYTES: usize = 16720;
pub const SPHINCS_A_SHAKE_128s_PUBLICKEYBYTES: usize = 32;
pub const SPHINCS_A_SHAKE_128s_SECRETKEYBYTES: usize = 64;
pub const SPHINCS_A_SHAKE_128s_SIGBYTES: usize = 6880;
pub const SPHINCS_A_SHAKE_192f_PUBLICKEYBYTES: usize = 48;
pub const SPHINCS_A_SHAKE_192f_SECRETKEYBYTES: usize = 96;
pub const SPHINCS_A_SHAKE_192f_SIGBYTES: usize = 34896;
pub const SPHINCS_A_SHAKE_192s_PUBLICKEYBYTES: usize = 48;
pub const SPHINCS_A_SHAKE_192s_SECRETKEYBYTES: usize = 96;
pub const SPHINCS_A_SHAKE_192s_SIGBYTES: usize = 14568;
pub const SPHINCS_A_SHAKE_256f_PUBLICKEYBYTES: usize = 64;
pub const SPHINCS_A_SHAKE_256f_SECRETKEYBYTES: usize = 128;
pub const SPHINCS_A_SHAKE_256f_SIGBYTES: usize = 49312;
pub const SPHINCS_A_SHAKE_256s_PUBLICKEYBYTES: usize = 64;
pub const SPHINCS_A_SHAKE_256s_SECRETKEYBYTES: usize = 128;
pub const SPHINCS_A_SHAKE_256s_SIGBYTES: usize = 27232;
pub const SPHINCS_A_SM3_128f_PUBLICKEYBYTES: usize = 32;
pub const SPHINCS_A_SM3_128f_SECRETKEYBYTES: usize = 64;
pub const SPHINCS_A_SM3_128f_SIGBYTES: usize = 16720;
pub const SPHINCS_A_SM3_128s_PUBLICKEYBYTES: usize = 32;
pub const SPHINCS_A_SM3_128s_SECRETKEYBYTES: usize = 64;
pub const SPHINCS_A_SM3_128s_SIGBYTES: usize = 6880;

unsafe extern "C" {
  pub fn pqmagic_sphincs_a_sha2_128f_simple_std_sign_keypair(
    pk: *mut ::core::ffi::c_uchar,
    sk: *mut ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_sphincs_a_sha2_128f_simple_std_sign_signature(
    sm: *mut ::core::ffi::c_uchar,
    smlen: *mut usize,
    m: *const ::core::ffi::c_uchar,
    mlen: usize,
    sk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_sphincs_a_sha2_128f_simple_std_sign_verify(
    sm: *const ::core::ffi::c_uchar,
    smlen: usize,
    m: *const ::core::ffi::c_uchar,
    mlen: usize,
    pk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_sphincs_a_sha2_128f_simple_std_sign(
    sm: *mut ::core::ffi::c_uchar,
    smlen: *mut usize,
    m: *const ::core::ffi::c_uchar,
    mlen: usize,
    sk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_sphincs_a_sha2_128f_simple_std_sign_open(
    m: *mut ::core::ffi::c_uchar,
    mlen: *mut usize,
    sm: *const ::core::ffi::c_uchar,
    smlen: usize,
    pk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_sphincs_a_sha2_128s_simple_std_sign_keypair(
    pk: *mut ::core::ffi::c_uchar,
    sk: *mut ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_sphincs_a_sha2_128s_simple_std_sign_signature(
    sm: *mut ::core::ffi::c_uchar,
    smlen: *mut usize,
    m: *const ::core::ffi::c_uchar,
    mlen: usize,
    sk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_sphincs_a_sha2_128s_simple_std_sign_verify(
    sm: *const ::core::ffi::c_uchar,
    smlen: usize,
    m: *const ::core::ffi::c_uchar,
    mlen: usize,
    pk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_sphincs_a_sha2_128s_simple_std_sign(
    sm: *mut ::core::ffi::c_uchar,
    smlen: *mut usize,
    m: *const ::core::ffi::c_uchar,
    mlen: usize,
    sk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_sphincs_a_sha2_128s_simple_std_sign_open(
    m: *mut ::core::ffi::c_uchar,
    mlen: *mut usize,
    sm: *const ::core::ffi::c_uchar,
    smlen: usize,
    pk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_sphincs_a_sha2_192f_simple_std_sign_keypair(
    pk: *mut ::core::ffi::c_uchar,
    sk: *mut ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_sphincs_a_sha2_192f_simple_std_sign_signature(
    sm: *mut ::core::ffi::c_uchar,
    smlen: *mut usize,
    m: *const ::core::ffi::c_uchar,
    mlen: usize,
    sk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_sphincs_a_sha2_192f_simple_std_sign_verify(
    sm: *const ::core::ffi::c_uchar,
    smlen: usize,
    m: *const ::core::ffi::c_uchar,
    mlen: usize,
    pk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_sphincs_a_sha2_192f_simple_std_sign(
    sm: *mut ::core::ffi::c_uchar,
    smlen: *mut usize,
    m: *const ::core::ffi::c_uchar,
    mlen: usize,
    sk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_sphincs_a_sha2_192f_simple_std_sign_open(
    m: *mut ::core::ffi::c_uchar,
    mlen: *mut usize,
    sm: *const ::core::ffi::c_uchar,
    smlen: usize,
    pk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_sphincs_a_sha2_192s_simple_std_sign_keypair(
    pk: *mut ::core::ffi::c_uchar,
    sk: *mut ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_sphincs_a_sha2_192s_simple_std_sign_signature(
    sm: *mut ::core::ffi::c_uchar,
    smlen: *mut usize,
    m: *const ::core::ffi::c_uchar,
    mlen: usize,
    sk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_sphincs_a_sha2_192s_simple_std_sign_verify(
    sm: *const ::core::ffi::c_uchar,
    smlen: usize,
    m: *const ::core::ffi::c_uchar,
    mlen: usize,
    pk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_sphincs_a_sha2_192s_simple_std_sign(
    sm: *mut ::core::ffi::c_uchar,
    smlen: *mut usize,
    m: *const ::core::ffi::c_uchar,
    mlen: usize,
    sk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_sphincs_a_sha2_192s_simple_std_sign_open(
    m: *mut ::core::ffi::c_uchar,
    mlen: *mut usize,
    sm: *const ::core::ffi::c_uchar,
    smlen: usize,
    pk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_sphincs_a_sha2_256f_simple_std_sign_keypair(
    pk: *mut ::core::ffi::c_uchar,
    sk: *mut ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_sphincs_a_sha2_256f_simple_std_sign_signature(
    sm: *mut ::core::ffi::c_uchar,
    smlen: *mut usize,
    m: *const ::core::ffi::c_uchar,
    mlen: usize,
    sk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_sphincs_a_sha2_256f_simple_std_sign_verify(
    sm: *const ::core::ffi::c_uchar,
    smlen: usize,
    m: *const ::core::ffi::c_uchar,
    mlen: usize,
    pk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_sphincs_a_sha2_256f_simple_std_sign(
    sm: *mut ::core::ffi::c_uchar,
    smlen: *mut usize,
    m: *const ::core::ffi::c_uchar,
    mlen: usize,
    sk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_sphincs_a_sha2_256f_simple_std_sign_open(
    m: *mut ::core::ffi::c_uchar,
    mlen: *mut usize,
    sm: *const ::core::ffi::c_uchar,
    smlen: usize,
    pk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_sphincs_a_sha2_256s_simple_std_sign_keypair(
    pk: *mut ::core::ffi::c_uchar,
    sk: *mut ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_sphincs_a_sha2_256s_simple_std_sign_signature(
    sm: *mut ::core::ffi::c_uchar,
    smlen: *mut usize,
    m: *const ::core::ffi::c_uchar,
    mlen: usize,
    sk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_sphincs_a_sha2_256s_simple_std_sign_verify(
    sm: *const ::core::ffi::c_uchar,
    smlen: usize,
    m: *const ::core::ffi::c_uchar,
    mlen: usize,
    pk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_sphincs_a_sha2_256s_simple_std_sign(
    sm: *mut ::core::ffi::c_uchar,
    smlen: *mut usize,
    m: *const ::core::ffi::c_uchar,
    mlen: usize,
    sk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_sphincs_a_sha2_256s_simple_std_sign_open(
    m: *mut ::core::ffi::c_uchar,
    mlen: *mut usize,
    sm: *const ::core::ffi::c_uchar,
    smlen: usize,
    pk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_sphincs_a_shake_128f_simple_std_sign_keypair(
    pk: *mut ::core::ffi::c_uchar,
    sk: *mut ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_sphincs_a_shake_128f_simple_std_sign_signature(
    sm: *mut ::core::ffi::c_uchar,
    smlen: *mut usize,
    m: *const ::core::ffi::c_uchar,
    mlen: usize,
    sk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_sphincs_a_shake_128f_simple_std_sign_verify(
    sm: *const ::core::ffi::c_uchar,
    smlen: usize,
    m: *const ::core::ffi::c_uchar,
    mlen: usize,
    pk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_sphincs_a_shake_128f_simple_std_sign(
    sm: *mut ::core::ffi::c_uchar,
    smlen: *mut usize,
    m: *const ::core::ffi::c_uchar,
    mlen: usize,
    sk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_sphincs_a_shake_128f_simple_std_sign_open(
    m: *mut ::core::ffi::c_uchar,
    mlen: *mut usize,
    sm: *const ::core::ffi::c_uchar,
    smlen: usize,
    pk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_sphincs_a_shake_128s_simple_std_sign_keypair(
    pk: *mut ::core::ffi::c_uchar,
    sk: *mut ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_sphincs_a_shake_128s_simple_std_sign_signature(
    sm: *mut ::core::ffi::c_uchar,
    smlen: *mut usize,
    m: *const ::core::ffi::c_uchar,
    mlen: usize,
    sk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_sphincs_a_shake_128s_simple_std_sign_verify(
    sm: *const ::core::ffi::c_uchar,
    smlen: usize,
    m: *const ::core::ffi::c_uchar,
    mlen: usize,
    pk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_sphincs_a_shake_128s_simple_std_sign(
    sm: *mut ::core::ffi::c_uchar,
    smlen: *mut usize,
    m: *const ::core::ffi::c_uchar,
    mlen: usize,
    sk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_sphincs_a_shake_128s_simple_std_sign_open(
    m: *mut ::core::ffi::c_uchar,
    mlen: *mut usize,
    sm: *const ::core::ffi::c_uchar,
    smlen: usize,
    pk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_sphincs_a_shake_192f_simple_std_sign_keypair(
    pk: *mut ::core::ffi::c_uchar,
    sk: *mut ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_sphincs_a_shake_192f_simple_std_sign_signature(
    sm: *mut ::core::ffi::c_uchar,
    smlen: *mut usize,
    m: *const ::core::ffi::c_uchar,
    mlen: usize,
    sk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_sphincs_a_shake_192f_simple_std_sign_verify(
    sm: *const ::core::ffi::c_uchar,
    smlen: usize,
    m: *const ::core::ffi::c_uchar,
    mlen: usize,
    pk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_sphincs_a_shake_192f_simple_std_sign(
    sm: *mut ::core::ffi::c_uchar,
    smlen: *mut usize,
    m: *const ::core::ffi::c_uchar,
    mlen: usize,
    sk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_sphincs_a_shake_192f_simple_std_sign_open(
    m: *mut ::core::ffi::c_uchar,
    mlen: *mut usize,
    sm: *const ::core::ffi::c_uchar,
    smlen: usize,
    pk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_sphincs_a_shake_192s_simple_std_sign_keypair(
    pk: *mut ::core::ffi::c_uchar,
    sk: *mut ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_sphincs_a_shake_192s_simple_std_sign_signature(
    sm: *mut ::core::ffi::c_uchar,
    smlen: *mut usize,
    m: *const ::core::ffi::c_uchar,
    mlen: usize,
    sk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_sphincs_a_shake_192s_simple_std_sign_verify(
    sm: *const ::core::ffi::c_uchar,
    smlen: usize,
    m: *const ::core::ffi::c_uchar,
    mlen: usize,
    pk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_sphincs_a_shake_192s_simple_std_sign(
    sm: *mut ::core::ffi::c_uchar,
    smlen: *mut usize,
    m: *const ::core::ffi::c_uchar,
    mlen: usize,
    sk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_sphincs_a_shake_192s_simple_std_sign_open(
    m: *mut ::core::ffi::c_uchar,
    mlen: *mut usize,
    sm: *const ::core::ffi::c_uchar,
    smlen: usize,
    pk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_sphincs_a_shake_256f_simple_std_sign_keypair(
    pk: *mut ::core::ffi::c_uchar,
    sk: *mut ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_sphincs_a_shake_256f_simple_std_sign_signature(
    sm: *mut ::core::ffi::c_uchar,
    smlen: *mut usize,
    m: *const ::core::ffi::c_uchar,
    mlen: usize,
    sk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_sphincs_a_shake_256f_simple_std_sign_verify(
    sm: *const ::core::ffi::c_uchar,
    smlen: usize,
    m: *const ::core::ffi::c_uchar,
    mlen: usize,
    pk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_sphincs_a_shake_256f_simple_std_sign(
    sm: *mut ::core::ffi::c_uchar,
    smlen: *mut usize,
    m: *const ::core::ffi::c_uchar,
    mlen: usize,
    sk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_sphincs_a_shake_256f_simple_std_sign_open(
    m: *mut ::core::ffi::c_uchar,
    mlen: *mut usize,
    sm: *const ::core::ffi::c_uchar,
    smlen: usize,
    pk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_sphincs_a_shake_256s_simple_std_sign_keypair(
    pk: *mut ::core::ffi::c_uchar,
    sk: *mut ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_sphincs_a_shake_256s_simple_std_sign_signature(
    sm: *mut ::core::ffi::c_uchar,
    smlen: *mut usize,
    m: *const ::core::ffi::c_uchar,
    mlen: usize,
    sk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_sphincs_a_shake_256s_simple_std_sign_verify(
    sm: *const ::core::ffi::c_uchar,
    smlen: usize,
    m: *const ::core::ffi::c_uchar,
    mlen: usize,
    pk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_sphincs_a_shake_256s_simple_std_sign(
    sm: *mut ::core::ffi::c_uchar,
    smlen: *mut usize,
    m: *const ::core::ffi::c_uchar,
    mlen: usize,
    sk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_sphincs_a_shake_256s_simple_std_sign_open(
    m: *mut ::core::ffi::c_uchar,
    mlen: *mut usize,
    sm: *const ::core::ffi::c_uchar,
    smlen: usize,
    pk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_sphincs_a_sm3_128f_simple_std_sign_keypair(
    pk: *mut ::core::ffi::c_uchar,
    sk: *mut ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_sphincs_a_sm3_128f_simple_std_sign_signature(
    sm: *mut ::core::ffi::c_uchar,
    smlen: *mut usize,
    m: *const ::core::ffi::c_uchar,
    mlen: usize,
    sk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_sphincs_a_sm3_128f_simple_std_sign_verify(
    sm: *const ::core::ffi::c_uchar,
    smlen: usize,
    m: *const ::core::ffi::c_uchar,
    mlen: usize,
    pk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_sphincs_a_sm3_128f_simple_std_sign(
    sm: *mut ::core::ffi::c_uchar,
    smlen: *mut usize,
    m: *const ::core::ffi::c_uchar,
    mlen: usize,
    sk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_sphincs_a_sm3_128f_simple_std_sign_open(
    m: *mut ::core::ffi::c_uchar,
    mlen: *mut usize,
    sm: *const ::core::ffi::c_uchar,
    smlen: usize,
    pk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_sphincs_a_sm3_128s_simple_std_sign_keypair(
    pk: *mut ::core::ffi::c_uchar,
    sk: *mut ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_sphincs_a_sm3_128s_simple_std_sign_signature(
    sm: *mut ::core::ffi::c_uchar,
    smlen: *mut usize,
    m: *const ::core::ffi::c_uchar,
    mlen: usize,
    sk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_sphincs_a_sm3_128s_simple_std_sign_verify(
    sm: *const ::core::ffi::c_uchar,
    smlen: usize,
    m: *const ::core::ffi::c_uchar,
    mlen: usize,
    pk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_sphincs_a_sm3_128s_simple_std_sign(
    sm: *mut ::core::ffi::c_uchar,
    smlen: *mut usize,
    m: *const ::core::ffi::c_uchar,
    mlen: usize,
    sk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
unsafe extern "C" {
  pub fn pqmagic_sphincs_a_sm3_128s_simple_std_sign_open(
    m: *mut ::core::ffi::c_uchar,
    mlen: *mut usize,
    sm: *const ::core::ffi::c_uchar,
    smlen: usize,
    pk: *const ::core::ffi::c_uchar,
  ) -> ::core::ffi::c_int;
}
