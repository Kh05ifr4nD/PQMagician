use ::core::ffi::c_int;

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
#[cfg(feature = "shake")]
pub const SPHINCS_A_SHAKE_128f_PUBLICKEYBYTES: usize = 32;
#[cfg(feature = "shake")]
pub const SPHINCS_A_SHAKE_128f_SECRETKEYBYTES: usize = 64;
#[cfg(feature = "shake")]
pub const SPHINCS_A_SHAKE_128f_SIGBYTES: usize = 16720;
#[cfg(feature = "shake")]
pub const SPHINCS_A_SHAKE_128s_PUBLICKEYBYTES: usize = 32;
#[cfg(feature = "shake")]
pub const SPHINCS_A_SHAKE_128s_SECRETKEYBYTES: usize = 64;
#[cfg(feature = "shake")]
pub const SPHINCS_A_SHAKE_128s_SIGBYTES: usize = 6880;
#[cfg(feature = "shake")]
pub const SPHINCS_A_SHAKE_192f_PUBLICKEYBYTES: usize = 48;
#[cfg(feature = "shake")]
pub const SPHINCS_A_SHAKE_192f_SECRETKEYBYTES: usize = 96;
#[cfg(feature = "shake")]
pub const SPHINCS_A_SHAKE_192f_SIGBYTES: usize = 34896;
#[cfg(feature = "shake")]
pub const SPHINCS_A_SHAKE_192s_PUBLICKEYBYTES: usize = 48;
#[cfg(feature = "shake")]
pub const SPHINCS_A_SHAKE_192s_SECRETKEYBYTES: usize = 96;
#[cfg(feature = "shake")]
pub const SPHINCS_A_SHAKE_192s_SIGBYTES: usize = 14568;
#[cfg(feature = "shake")]
pub const SPHINCS_A_SHAKE_256f_PUBLICKEYBYTES: usize = 64;
#[cfg(feature = "shake")]
pub const SPHINCS_A_SHAKE_256f_SECRETKEYBYTES: usize = 128;
#[cfg(feature = "shake")]
pub const SPHINCS_A_SHAKE_256f_SIGBYTES: usize = 49312;
#[cfg(feature = "shake")]
pub const SPHINCS_A_SHAKE_256s_PUBLICKEYBYTES: usize = 64;
#[cfg(feature = "shake")]
pub const SPHINCS_A_SHAKE_256s_SECRETKEYBYTES: usize = 128;
#[cfg(feature = "shake")]
pub const SPHINCS_A_SHAKE_256s_SIGBYTES: usize = 27232;
#[cfg(feature = "sm3")]
pub const SPHINCS_A_SM3_128f_PUBLICKEYBYTES: usize = 32;
#[cfg(feature = "sm3")]
pub const SPHINCS_A_SM3_128f_SECRETKEYBYTES: usize = 64;
#[cfg(feature = "sm3")]
pub const SPHINCS_A_SM3_128f_SIGBYTES: usize = 16720;
#[cfg(feature = "sm3")]
pub const SPHINCS_A_SM3_128s_PUBLICKEYBYTES: usize = 32;
#[cfg(feature = "sm3")]
pub const SPHINCS_A_SM3_128s_SECRETKEYBYTES: usize = 64;
#[cfg(feature = "sm3")]
pub const SPHINCS_A_SM3_128s_SIGBYTES: usize = 6880;

extern "C" {
  pub fn pqmagic_sphincs_a_sha2_128f_simple_std_sign_keypair(pk: *mut u8, sk: *mut u8) -> c_int;

  pub fn pqmagic_sphincs_a_sha2_128f_simple_std_sign_signature(
    sm: *mut u8,
    sm_len: *mut usize,
    m: *const u8,
    m_len: usize,
    sk: *const u8,
  ) -> c_int;

  pub fn pqmagic_sphincs_a_sha2_128f_simple_std_sign_verify(
    sm: *const u8,
    sm_len: usize,
    m: *const u8,
    m_len: usize,
    pk: *const u8,
  ) -> c_int;

  pub fn pqmagic_sphincs_a_sha2_128f_simple_std_sign(
    sm: *mut u8,
    sm_len: *mut usize,
    m: *const u8,
    m_len: usize,
    sk: *const u8,
  ) -> c_int;

  pub fn pqmagic_sphincs_a_sha2_128f_simple_std_sign_open(
    m: *mut u8,
    m_len: *mut usize,
    sm: *const u8,
    sm_len: usize,
    pk: *const u8,
  ) -> c_int;

  pub fn pqmagic_sphincs_a_sha2_128s_simple_std_sign_keypair(pk: *mut u8, sk: *mut u8) -> c_int;

  pub fn pqmagic_sphincs_a_sha2_128s_simple_std_sign_signature(
    sm: *mut u8,
    sm_len: *mut usize,
    m: *const u8,
    m_len: usize,
    sk: *const u8,
  ) -> c_int;

  pub fn pqmagic_sphincs_a_sha2_128s_simple_std_sign_verify(
    sm: *const u8,
    sm_len: usize,
    m: *const u8,
    m_len: usize,
    pk: *const u8,
  ) -> c_int;

  pub fn pqmagic_sphincs_a_sha2_128s_simple_std_sign(
    sm: *mut u8,
    sm_len: *mut usize,
    m: *const u8,
    m_len: usize,
    sk: *const u8,
  ) -> c_int;

  pub fn pqmagic_sphincs_a_sha2_128s_simple_std_sign_open(
    m: *mut u8,
    m_len: *mut usize,
    sm: *const u8,
    sm_len: usize,
    pk: *const u8,
  ) -> c_int;

  pub fn pqmagic_sphincs_a_sha2_192f_simple_std_sign_keypair(pk: *mut u8, sk: *mut u8) -> c_int;

  pub fn pqmagic_sphincs_a_sha2_192f_simple_std_sign_signature(
    sm: *mut u8,
    sm_len: *mut usize,
    m: *const u8,
    m_len: usize,
    sk: *const u8,
  ) -> c_int;

  pub fn pqmagic_sphincs_a_sha2_192f_simple_std_sign_verify(
    sm: *const u8,
    sm_len: usize,
    m: *const u8,
    m_len: usize,
    pk: *const u8,
  ) -> c_int;

  pub fn pqmagic_sphincs_a_sha2_192f_simple_std_sign(
    sm: *mut u8,
    sm_len: *mut usize,
    m: *const u8,
    m_len: usize,
    sk: *const u8,
  ) -> c_int;

  pub fn pqmagic_sphincs_a_sha2_192f_simple_std_sign_open(
    m: *mut u8,
    m_len: *mut usize,
    sm: *const u8,
    sm_len: usize,
    pk: *const u8,
  ) -> c_int;

  pub fn pqmagic_sphincs_a_sha2_192s_simple_std_sign_keypair(pk: *mut u8, sk: *mut u8) -> c_int;

  pub fn pqmagic_sphincs_a_sha2_192s_simple_std_sign_signature(
    sm: *mut u8,
    sm_len: *mut usize,
    m: *const u8,
    m_len: usize,
    sk: *const u8,
  ) -> c_int;

  pub fn pqmagic_sphincs_a_sha2_192s_simple_std_sign_verify(
    sm: *const u8,
    sm_len: usize,
    m: *const u8,
    m_len: usize,
    pk: *const u8,
  ) -> c_int;

  pub fn pqmagic_sphincs_a_sha2_192s_simple_std_sign(
    sm: *mut u8,
    sm_len: *mut usize,
    m: *const u8,
    m_len: usize,
    sk: *const u8,
  ) -> c_int;

  pub fn pqmagic_sphincs_a_sha2_192s_simple_std_sign_open(
    m: *mut u8,
    m_len: *mut usize,
    sm: *const u8,
    sm_len: usize,
    pk: *const u8,
  ) -> c_int;

  pub fn pqmagic_sphincs_a_sha2_256f_simple_std_sign_keypair(pk: *mut u8, sk: *mut u8) -> c_int;

  pub fn pqmagic_sphincs_a_sha2_256f_simple_std_sign_signature(
    sm: *mut u8,
    sm_len: *mut usize,
    m: *const u8,
    m_len: usize,
    sk: *const u8,
  ) -> c_int;

  pub fn pqmagic_sphincs_a_sha2_256f_simple_std_sign_verify(
    sm: *const u8,
    sm_len: usize,
    m: *const u8,
    m_len: usize,
    pk: *const u8,
  ) -> c_int;

  pub fn pqmagic_sphincs_a_sha2_256f_simple_std_sign(
    sm: *mut u8,
    sm_len: *mut usize,
    m: *const u8,
    m_len: usize,
    sk: *const u8,
  ) -> c_int;

  pub fn pqmagic_sphincs_a_sha2_256f_simple_std_sign_open(
    m: *mut u8,
    m_len: *mut usize,
    sm: *const u8,
    sm_len: usize,
    pk: *const u8,
  ) -> c_int;

  pub fn pqmagic_sphincs_a_sha2_256s_simple_std_sign_keypair(pk: *mut u8, sk: *mut u8) -> c_int;

  pub fn pqmagic_sphincs_a_sha2_256s_simple_std_sign_signature(
    sm: *mut u8,
    sm_len: *mut usize,
    m: *const u8,
    m_len: usize,
    sk: *const u8,
  ) -> c_int;

  pub fn pqmagic_sphincs_a_sha2_256s_simple_std_sign_verify(
    sm: *const u8,
    sm_len: usize,
    m: *const u8,
    m_len: usize,
    pk: *const u8,
  ) -> c_int;

  pub fn pqmagic_sphincs_a_sha2_256s_simple_std_sign(
    sm: *mut u8,
    sm_len: *mut usize,
    m: *const u8,
    m_len: usize,
    sk: *const u8,
  ) -> c_int;

  pub fn pqmagic_sphincs_a_sha2_256s_simple_std_sign_open(
    m: *mut u8,
    m_len: *mut usize,
    sm: *const u8,
    sm_len: usize,
    pk: *const u8,
  ) -> c_int;

  #[cfg(feature = "shake")]
  pub fn pqmagic_sphincs_a_shake_128f_simple_std_sign_keypair(pk: *mut u8, sk: *mut u8) -> c_int;

  #[cfg(feature = "shake")]
  pub fn pqmagic_sphincs_a_shake_128f_simple_std_sign_signature(
    sm: *mut u8,
    sm_len: *mut usize,
    m: *const u8,
    m_len: usize,
    sk: *const u8,
  ) -> c_int;

  #[cfg(feature = "shake")]
  pub fn pqmagic_sphincs_a_shake_128f_simple_std_sign_verify(
    sm: *const u8,
    sm_len: usize,
    m: *const u8,
    m_len: usize,
    pk: *const u8,
  ) -> c_int;

  #[cfg(feature = "shake")]
  pub fn pqmagic_sphincs_a_shake_128f_simple_std_sign(
    sm: *mut u8,
    sm_len: *mut usize,
    m: *const u8,
    m_len: usize,
    sk: *const u8,
  ) -> c_int;

  #[cfg(feature = "shake")]
  pub fn pqmagic_sphincs_a_shake_128f_simple_std_sign_open(
    m: *mut u8,
    m_len: *mut usize,
    sm: *const u8,
    sm_len: usize,
    pk: *const u8,
  ) -> c_int;

  #[cfg(feature = "shake")]
  pub fn pqmagic_sphincs_a_shake_128s_simple_std_sign_keypair(pk: *mut u8, sk: *mut u8) -> c_int;

  #[cfg(feature = "shake")]
  pub fn pqmagic_sphincs_a_shake_128s_simple_std_sign_signature(
    sm: *mut u8,
    sm_len: *mut usize,
    m: *const u8,
    m_len: usize,
    sk: *const u8,
  ) -> c_int;

  #[cfg(feature = "shake")]
  pub fn pqmagic_sphincs_a_shake_128s_simple_std_sign_verify(
    sm: *const u8,
    sm_len: usize,
    m: *const u8,
    m_len: usize,
    pk: *const u8,
  ) -> c_int;

  #[cfg(feature = "shake")]
  pub fn pqmagic_sphincs_a_shake_128s_simple_std_sign(
    sm: *mut u8,
    sm_len: *mut usize,
    m: *const u8,
    m_len: usize,
    sk: *const u8,
  ) -> c_int;

  #[cfg(feature = "shake")]
  pub fn pqmagic_sphincs_a_shake_128s_simple_std_sign_open(
    m: *mut u8,
    m_len: *mut usize,
    sm: *const u8,
    sm_len: usize,
    pk: *const u8,
  ) -> c_int;

  #[cfg(feature = "shake")]
  pub fn pqmagic_sphincs_a_shake_192f_simple_std_sign_keypair(pk: *mut u8, sk: *mut u8) -> c_int;

  #[cfg(feature = "shake")]
  pub fn pqmagic_sphincs_a_shake_192f_simple_std_sign_signature(
    sm: *mut u8,
    sm_len: *mut usize,
    m: *const u8,
    m_len: usize,
    sk: *const u8,
  ) -> c_int;

  #[cfg(feature = "shake")]
  pub fn pqmagic_sphincs_a_shake_192f_simple_std_sign_verify(
    sm: *const u8,
    sm_len: usize,
    m: *const u8,
    m_len: usize,
    pk: *const u8,
  ) -> c_int;

  #[cfg(feature = "shake")]
  pub fn pqmagic_sphincs_a_shake_192f_simple_std_sign(
    sm: *mut u8,
    sm_len: *mut usize,
    m: *const u8,
    m_len: usize,
    sk: *const u8,
  ) -> c_int;

  #[cfg(feature = "shake")]
  pub fn pqmagic_sphincs_a_shake_192f_simple_std_sign_open(
    m: *mut u8,
    m_len: *mut usize,
    sm: *const u8,
    sm_len: usize,
    pk: *const u8,
  ) -> c_int;

  #[cfg(feature = "shake")]
  pub fn pqmagic_sphincs_a_shake_192s_simple_std_sign_keypair(pk: *mut u8, sk: *mut u8) -> c_int;

  #[cfg(feature = "shake")]
  pub fn pqmagic_sphincs_a_shake_192s_simple_std_sign_signature(
    sm: *mut u8,
    sm_len: *mut usize,
    m: *const u8,
    m_len: usize,
    sk: *const u8,
  ) -> c_int;

  #[cfg(feature = "shake")]
  pub fn pqmagic_sphincs_a_shake_192s_simple_std_sign_verify(
    sm: *const u8,
    sm_len: usize,
    m: *const u8,
    m_len: usize,
    pk: *const u8,
  ) -> c_int;

  #[cfg(feature = "shake")]
  pub fn pqmagic_sphincs_a_shake_192s_simple_std_sign(
    sm: *mut u8,
    sm_len: *mut usize,
    m: *const u8,
    m_len: usize,
    sk: *const u8,
  ) -> c_int;

  #[cfg(feature = "shake")]
  pub fn pqmagic_sphincs_a_shake_192s_simple_std_sign_open(
    m: *mut u8,
    m_len: *mut usize,
    sm: *const u8,
    sm_len: usize,
    pk: *const u8,
  ) -> c_int;

  #[cfg(feature = "shake")]
  pub fn pqmagic_sphincs_a_shake_256f_simple_std_sign_keypair(pk: *mut u8, sk: *mut u8) -> c_int;

  #[cfg(feature = "shake")]
  pub fn pqmagic_sphincs_a_shake_256f_simple_std_sign_signature(
    sm: *mut u8,
    sm_len: *mut usize,
    m: *const u8,
    m_len: usize,
    sk: *const u8,
  ) -> c_int;

  #[cfg(feature = "shake")]
  pub fn pqmagic_sphincs_a_shake_256f_simple_std_sign_verify(
    sm: *const u8,
    sm_len: usize,
    m: *const u8,
    m_len: usize,
    pk: *const u8,
  ) -> c_int;

  #[cfg(feature = "shake")]
  pub fn pqmagic_sphincs_a_shake_256f_simple_std_sign(
    sm: *mut u8,
    sm_len: *mut usize,
    m: *const u8,
    m_len: usize,
    sk: *const u8,
  ) -> c_int;

  #[cfg(feature = "shake")]
  pub fn pqmagic_sphincs_a_shake_256f_simple_std_sign_open(
    m: *mut u8,
    m_len: *mut usize,
    sm: *const u8,
    sm_len: usize,
    pk: *const u8,
  ) -> c_int;

  #[cfg(feature = "shake")]
  pub fn pqmagic_sphincs_a_shake_256s_simple_std_sign_keypair(pk: *mut u8, sk: *mut u8) -> c_int;

  #[cfg(feature = "shake")]
  pub fn pqmagic_sphincs_a_shake_256s_simple_std_sign_signature(
    sm: *mut u8,
    sm_len: *mut usize,
    m: *const u8,
    m_len: usize,
    sk: *const u8,
  ) -> c_int;

  #[cfg(feature = "shake")]
  pub fn pqmagic_sphincs_a_shake_256s_simple_std_sign_verify(
    sm: *const u8,
    sm_len: usize,
    m: *const u8,
    m_len: usize,
    pk: *const u8,
  ) -> c_int;

  #[cfg(feature = "shake")]
  pub fn pqmagic_sphincs_a_shake_256s_simple_std_sign(
    sm: *mut u8,
    sm_len: *mut usize,
    m: *const u8,
    m_len: usize,
    sk: *const u8,
  ) -> c_int;

  #[cfg(feature = "shake")]
  pub fn pqmagic_sphincs_a_shake_256s_simple_std_sign_open(
    m: *mut u8,
    m_len: *mut usize,
    sm: *const u8,
    sm_len: usize,
    pk: *const u8,
  ) -> c_int;

  #[cfg(feature = "sm3")]
  pub fn pqmagic_sphincs_a_sm3_128f_simple_std_sign_keypair(pk: *mut u8, sk: *mut u8) -> c_int;

  #[cfg(feature = "sm3")]
  pub fn pqmagic_sphincs_a_sm3_128f_simple_std_sign_signature(
    sm: *mut u8,
    sm_len: *mut usize,
    m: *const u8,
    m_len: usize,
    sk: *const u8,
  ) -> c_int;

  #[cfg(feature = "sm3")]
  pub fn pqmagic_sphincs_a_sm3_128f_simple_std_sign_verify(
    sm: *const u8,
    sm_len: usize,
    m: *const u8,
    m_len: usize,
    pk: *const u8,
  ) -> c_int;

  #[cfg(feature = "sm3")]
  pub fn pqmagic_sphincs_a_sm3_128f_simple_std_sign(
    sm: *mut u8,
    sm_len: *mut usize,
    m: *const u8,
    m_len: usize,
    sk: *const u8,
  ) -> c_int;

  #[cfg(feature = "sm3")]
  pub fn pqmagic_sphincs_a_sm3_128f_simple_std_sign_open(
    m: *mut u8,
    m_len: *mut usize,
    sm: *const u8,
    sm_len: usize,
    pk: *const u8,
  ) -> c_int;

  #[cfg(feature = "sm3")]
  pub fn pqmagic_sphincs_a_sm3_128s_simple_std_sign_keypair(pk: *mut u8, sk: *mut u8) -> c_int;

  #[cfg(feature = "sm3")]
  pub fn pqmagic_sphincs_a_sm3_128s_simple_std_sign_signature(
    sm: *mut u8,
    sm_len: *mut usize,
    m: *const u8,
    m_len: usize,
    sk: *const u8,
  ) -> c_int;

  #[cfg(feature = "sm3")]
  pub fn pqmagic_sphincs_a_sm3_128s_simple_std_sign_verify(
    sm: *const u8,
    sm_len: usize,
    m: *const u8,
    m_len: usize,
    pk: *const u8,
  ) -> c_int;

  #[cfg(feature = "sm3")]
  pub fn pqmagic_sphincs_a_sm3_128s_simple_std_sign(
    sm: *mut u8,
    sm_len: *mut usize,
    m: *const u8,
    m_len: usize,
    sk: *const u8,
  ) -> c_int;

  #[cfg(feature = "sm3")]
  pub fn pqmagic_sphincs_a_sm3_128s_simple_std_sign_open(
    m: *mut u8,
    m_len: *mut usize,
    sm: *const u8,
    sm_len: usize,
    pk: *const u8,
  ) -> c_int;
}
