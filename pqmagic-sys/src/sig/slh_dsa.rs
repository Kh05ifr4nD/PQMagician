use ::core::ffi::c_int;

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
#[cfg(feature = "shake")]
pub const SLH_DSA_SHAKE_128f_PUBLICKEYBYTES: usize = 32;
#[cfg(feature = "shake")]
pub const SLH_DSA_SHAKE_128f_SECRETKEYBYTES: usize = 64;
#[cfg(feature = "shake")]
pub const SLH_DSA_SHAKE_128f_SIGBYTES: usize = 17088;
#[cfg(feature = "shake")]
pub const SLH_DSA_SHAKE_128s_PUBLICKEYBYTES: usize = 32;
#[cfg(feature = "shake")]
pub const SLH_DSA_SHAKE_128s_SECRETKEYBYTES: usize = 64;
#[cfg(feature = "shake")]
pub const SLH_DSA_SHAKE_128s_SIGBYTES: usize = 7856;
#[cfg(feature = "shake")]
pub const SLH_DSA_SHAKE_192f_PUBLICKEYBYTES: usize = 48;
#[cfg(feature = "shake")]
pub const SLH_DSA_SHAKE_192f_SECRETKEYBYTES: usize = 96;
#[cfg(feature = "shake")]
pub const SLH_DSA_SHAKE_192f_SIGBYTES: usize = 35664;
#[cfg(feature = "shake")]
pub const SLH_DSA_SHAKE_192s_PUBLICKEYBYTES: usize = 48;
#[cfg(feature = "shake")]
pub const SLH_DSA_SHAKE_192s_SECRETKEYBYTES: usize = 96;
#[cfg(feature = "shake")]
pub const SLH_DSA_SHAKE_192s_SIGBYTES: usize = 16224;
#[cfg(feature = "shake")]
pub const SLH_DSA_SHAKE_256f_PUBLICKEYBYTES: usize = 64;
#[cfg(feature = "shake")]
pub const SLH_DSA_SHAKE_256f_SECRETKEYBYTES: usize = 128;
#[cfg(feature = "shake")]
pub const SLH_DSA_SHAKE_256f_SIGBYTES: usize = 49856;
#[cfg(feature = "shake")]
pub const SLH_DSA_SHAKE_256s_PUBLICKEYBYTES: usize = 64;
#[cfg(feature = "shake")]
pub const SLH_DSA_SHAKE_256s_SECRETKEYBYTES: usize = 128;
#[cfg(feature = "shake")]
pub const SLH_DSA_SHAKE_256s_SIGBYTES: usize = 29792;
#[cfg(feature = "sm3")]
pub const SLH_DSA_SM3_128f_PUBLICKEYBYTES: usize = 32;
#[cfg(feature = "sm3")]
pub const SLH_DSA_SM3_128f_SECRETKEYBYTES: usize = 64;
#[cfg(feature = "sm3")]
pub const SLH_DSA_SM3_128f_SIGBYTES: usize = 17088;
#[cfg(feature = "sm3")]
pub const SLH_DSA_SM3_128s_PUBLICKEYBYTES: usize = 32;
#[cfg(feature = "sm3")]
pub const SLH_DSA_SM3_128s_SECRETKEYBYTES: usize = 64;
#[cfg(feature = "sm3")]
pub const SLH_DSA_SM3_128s_SIGBYTES: usize = 7856;

unsafe extern "C" {
  pub fn pqmagic_slh_dsa_sha2_128f_simple_std_sign_keypair(pk: *mut u8, sk: *mut u8) -> c_int;

  pub fn pqmagic_slh_dsa_sha2_128f_simple_std_sign_signature(
    sm: *mut u8,
    sm_len: *mut usize,
    m: *const u8,
    m_len: usize,
    sk: *const u8,
  ) -> c_int;

  pub fn pqmagic_slh_dsa_sha2_128f_simple_std_sign_verify(
    sm: *const u8,
    sm_len: usize,
    m: *const u8,
    m_len: usize,
    pk: *const u8,
  ) -> c_int;

  pub fn pqmagic_slh_dsa_sha2_128f_simple_std_sign(
    sm: *mut u8,
    sm_len: *mut usize,
    m: *const u8,
    m_len: usize,
    sk: *const u8,
  ) -> c_int;

  pub fn pqmagic_slh_dsa_sha2_128f_simple_std_sign_open(
    m: *mut u8,
    m_len: *mut usize,
    sm: *const u8,
    sm_len: usize,
    pk: *const u8,
  ) -> c_int;

  pub fn pqmagic_slh_dsa_sha2_128s_simple_std_sign_keypair(pk: *mut u8, sk: *mut u8) -> c_int;

  pub fn pqmagic_slh_dsa_sha2_128s_simple_std_sign_signature(
    sm: *mut u8,
    sm_len: *mut usize,
    m: *const u8,
    m_len: usize,
    sk: *const u8,
  ) -> c_int;

  pub fn pqmagic_slh_dsa_sha2_128s_simple_std_sign_verify(
    sm: *const u8,
    sm_len: usize,
    m: *const u8,
    m_len: usize,
    pk: *const u8,
  ) -> c_int;

  pub fn pqmagic_slh_dsa_sha2_128s_simple_std_sign(
    sm: *mut u8,
    sm_len: *mut usize,
    m: *const u8,
    m_len: usize,
    sk: *const u8,
  ) -> c_int;

  pub fn pqmagic_slh_dsa_sha2_128s_simple_std_sign_open(
    m: *mut u8,
    m_len: *mut usize,
    sm: *const u8,
    sm_len: usize,
    pk: *const u8,
  ) -> c_int;

  pub fn pqmagic_slh_dsa_sha2_192f_simple_std_sign_keypair(pk: *mut u8, sk: *mut u8) -> c_int;

  pub fn pqmagic_slh_dsa_sha2_192f_simple_std_sign_signature(
    sm: *mut u8,
    sm_len: *mut usize,
    m: *const u8,
    m_len: usize,
    sk: *const u8,
  ) -> c_int;

  pub fn pqmagic_slh_dsa_sha2_192f_simple_std_sign_verify(
    sm: *const u8,
    sm_len: usize,
    m: *const u8,
    m_len: usize,
    pk: *const u8,
  ) -> c_int;

  pub fn pqmagic_slh_dsa_sha2_192f_simple_std_sign(
    sm: *mut u8,
    sm_len: *mut usize,
    m: *const u8,
    m_len: usize,
    sk: *const u8,
  ) -> c_int;

  pub fn pqmagic_slh_dsa_sha2_192f_simple_std_sign_open(
    m: *mut u8,
    m_len: *mut usize,
    sm: *const u8,
    sm_len: usize,
    pk: *const u8,
  ) -> c_int;

  pub fn pqmagic_slh_dsa_sha2_192s_simple_std_sign_keypair(pk: *mut u8, sk: *mut u8) -> c_int;

  pub fn pqmagic_slh_dsa_sha2_192s_simple_std_sign_signature(
    sm: *mut u8,
    sm_len: *mut usize,
    m: *const u8,
    m_len: usize,
    sk: *const u8,
  ) -> c_int;

  pub fn pqmagic_slh_dsa_sha2_192s_simple_std_sign_verify(
    sm: *const u8,
    sm_len: usize,
    m: *const u8,
    m_len: usize,
    pk: *const u8,
  ) -> c_int;

  pub fn pqmagic_slh_dsa_sha2_192s_simple_std_sign(
    sm: *mut u8,
    sm_len: *mut usize,
    m: *const u8,
    m_len: usize,
    sk: *const u8,
  ) -> c_int;

  pub fn pqmagic_slh_dsa_sha2_192s_simple_std_sign_open(
    m: *mut u8,
    m_len: *mut usize,
    sm: *const u8,
    sm_len: usize,
    pk: *const u8,
  ) -> c_int;

  pub fn pqmagic_slh_dsa_sha2_256f_simple_std_sign_keypair(pk: *mut u8, sk: *mut u8) -> c_int;

  pub fn pqmagic_slh_dsa_sha2_256f_simple_std_sign_signature(
    sm: *mut u8,
    sm_len: *mut usize,
    m: *const u8,
    m_len: usize,
    sk: *const u8,
  ) -> c_int;

  pub fn pqmagic_slh_dsa_sha2_256f_simple_std_sign_verify(
    sm: *const u8,
    sm_len: usize,
    m: *const u8,
    m_len: usize,
    pk: *const u8,
  ) -> c_int;

  pub fn pqmagic_slh_dsa_sha2_256f_simple_std_sign(
    sm: *mut u8,
    sm_len: *mut usize,
    m: *const u8,
    m_len: usize,
    sk: *const u8,
  ) -> c_int;

  pub fn pqmagic_slh_dsa_sha2_256f_simple_std_sign_open(
    m: *mut u8,
    m_len: *mut usize,
    sm: *const u8,
    sm_len: usize,
    pk: *const u8,
  ) -> c_int;

  pub fn pqmagic_slh_dsa_sha2_256s_simple_std_sign_keypair(pk: *mut u8, sk: *mut u8) -> c_int;

  pub fn pqmagic_slh_dsa_sha2_256s_simple_std_sign_signature(
    sm: *mut u8,
    sm_len: *mut usize,
    m: *const u8,
    m_len: usize,
    sk: *const u8,
  ) -> c_int;

  pub fn pqmagic_slh_dsa_sha2_256s_simple_std_sign_verify(
    sm: *const u8,
    sm_len: usize,
    m: *const u8,
    m_len: usize,
    pk: *const u8,
  ) -> c_int;

  pub fn pqmagic_slh_dsa_sha2_256s_simple_std_sign(
    sm: *mut u8,
    sm_len: *mut usize,
    m: *const u8,
    m_len: usize,
    sk: *const u8,
  ) -> c_int;

  pub fn pqmagic_slh_dsa_sha2_256s_simple_std_sign_open(
    m: *mut u8,
    m_len: *mut usize,
    sm: *const u8,
    sm_len: usize,
    pk: *const u8,
  ) -> c_int;

  #[cfg(feature = "shake")]
  pub fn pqmagic_slh_dsa_shake_128f_simple_std_sign_keypair(pk: *mut u8, sk: *mut u8) -> c_int;

  #[cfg(feature = "shake")]
  pub fn pqmagic_slh_dsa_shake_128f_simple_std_sign_signature(
    sm: *mut u8,
    sm_len: *mut usize,
    m: *const u8,
    m_len: usize,
    sk: *const u8,
  ) -> c_int;

  #[cfg(feature = "shake")]
  pub fn pqmagic_slh_dsa_shake_128f_simple_std_sign_verify(
    sm: *const u8,
    sm_len: usize,
    m: *const u8,
    m_len: usize,
    pk: *const u8,
  ) -> c_int;

  #[cfg(feature = "shake")]
  pub fn pqmagic_slh_dsa_shake_128f_simple_std_sign(
    sm: *mut u8,
    sm_len: *mut usize,
    m: *const u8,
    m_len: usize,
    sk: *const u8,
  ) -> c_int;

  #[cfg(feature = "shake")]
  pub fn pqmagic_slh_dsa_shake_128f_simple_std_sign_open(
    m: *mut u8,
    m_len: *mut usize,
    sm: *const u8,
    sm_len: usize,
    pk: *const u8,
  ) -> c_int;

  #[cfg(feature = "shake")]
  pub fn pqmagic_slh_dsa_shake_128s_simple_std_sign_keypair(pk: *mut u8, sk: *mut u8) -> c_int;

  #[cfg(feature = "shake")]
  pub fn pqmagic_slh_dsa_shake_128s_simple_std_sign_signature(
    sm: *mut u8,
    sm_len: *mut usize,
    m: *const u8,
    m_len: usize,
    sk: *const u8,
  ) -> c_int;

  #[cfg(feature = "shake")]
  pub fn pqmagic_slh_dsa_shake_128s_simple_std_sign_verify(
    sm: *const u8,
    sm_len: usize,
    m: *const u8,
    m_len: usize,
    pk: *const u8,
  ) -> c_int;

  #[cfg(feature = "shake")]
  pub fn pqmagic_slh_dsa_shake_128s_simple_std_sign(
    sm: *mut u8,
    sm_len: *mut usize,
    m: *const u8,
    m_len: usize,
    sk: *const u8,
  ) -> c_int;

  #[cfg(feature = "shake")]
  pub fn pqmagic_slh_dsa_shake_128s_simple_std_sign_open(
    m: *mut u8,
    m_len: *mut usize,
    sm: *const u8,
    sm_len: usize,
    pk: *const u8,
  ) -> c_int;

  #[cfg(feature = "shake")]
  pub fn pqmagic_slh_dsa_shake_192f_simple_std_sign_keypair(pk: *mut u8, sk: *mut u8) -> c_int;

  #[cfg(feature = "shake")]
  pub fn pqmagic_slh_dsa_shake_192f_simple_std_sign_signature(
    sm: *mut u8,
    sm_len: *mut usize,
    m: *const u8,
    m_len: usize,
    sk: *const u8,
  ) -> c_int;

  #[cfg(feature = "shake")]
  pub fn pqmagic_slh_dsa_shake_192f_simple_std_sign_verify(
    sm: *const u8,
    sm_len: usize,
    m: *const u8,
    m_len: usize,
    pk: *const u8,
  ) -> c_int;

  #[cfg(feature = "shake")]
  pub fn pqmagic_slh_dsa_shake_192f_simple_std_sign(
    sm: *mut u8,
    sm_len: *mut usize,
    m: *const u8,
    m_len: usize,
    sk: *const u8,
  ) -> c_int;

  #[cfg(feature = "shake")]
  pub fn pqmagic_slh_dsa_shake_192f_simple_std_sign_open(
    m: *mut u8,
    m_len: *mut usize,
    sm: *const u8,
    sm_len: usize,
    pk: *const u8,
  ) -> c_int;

  #[cfg(feature = "shake")]
  pub fn pqmagic_slh_dsa_shake_192s_simple_std_sign_keypair(pk: *mut u8, sk: *mut u8) -> c_int;

  #[cfg(feature = "shake")]
  pub fn pqmagic_slh_dsa_shake_192s_simple_std_sign_signature(
    sm: *mut u8,
    sm_len: *mut usize,
    m: *const u8,
    m_len: usize,
    sk: *const u8,
  ) -> c_int;

  #[cfg(feature = "shake")]
  pub fn pqmagic_slh_dsa_shake_192s_simple_std_sign_verify(
    sm: *const u8,
    sm_len: usize,
    m: *const u8,
    m_len: usize,
    pk: *const u8,
  ) -> c_int;

  #[cfg(feature = "shake")]
  pub fn pqmagic_slh_dsa_shake_192s_simple_std_sign(
    sm: *mut u8,
    sm_len: *mut usize,
    m: *const u8,
    m_len: usize,
    sk: *const u8,
  ) -> c_int;

  #[cfg(feature = "shake")]
  pub fn pqmagic_slh_dsa_shake_192s_simple_std_sign_open(
    m: *mut u8,
    m_len: *mut usize,
    sm: *const u8,
    sm_len: usize,
    pk: *const u8,
  ) -> c_int;

  #[cfg(feature = "shake")]
  pub fn pqmagic_slh_dsa_shake_256f_simple_std_sign_keypair(pk: *mut u8, sk: *mut u8) -> c_int;

  #[cfg(feature = "shake")]
  pub fn pqmagic_slh_dsa_shake_256f_simple_std_sign_signature(
    sm: *mut u8,
    sm_len: *mut usize,
    m: *const u8,
    m_len: usize,
    sk: *const u8,
  ) -> c_int;

  #[cfg(feature = "shake")]
  pub fn pqmagic_slh_dsa_shake_256f_simple_std_sign_verify(
    sm: *const u8,
    sm_len: usize,
    m: *const u8,
    m_len: usize,
    pk: *const u8,
  ) -> c_int;

  #[cfg(feature = "shake")]
  pub fn pqmagic_slh_dsa_shake_256f_simple_std_sign(
    sm: *mut u8,
    sm_len: *mut usize,
    m: *const u8,
    m_len: usize,
    sk: *const u8,
  ) -> c_int;

  #[cfg(feature = "shake")]
  pub fn pqmagic_slh_dsa_shake_256f_simple_std_sign_open(
    m: *mut u8,
    m_len: *mut usize,
    sm: *const u8,
    sm_len: usize,
    pk: *const u8,
  ) -> c_int;

  #[cfg(feature = "shake")]
  pub fn pqmagic_slh_dsa_shake_256s_simple_std_sign_keypair(pk: *mut u8, sk: *mut u8) -> c_int;

  #[cfg(feature = "shake")]
  pub fn pqmagic_slh_dsa_shake_256s_simple_std_sign_signature(
    sm: *mut u8,
    sm_len: *mut usize,
    m: *const u8,
    m_len: usize,
    sk: *const u8,
  ) -> c_int;

  #[cfg(feature = "shake")]
  pub fn pqmagic_slh_dsa_shake_256s_simple_std_sign_verify(
    sm: *const u8,
    sm_len: usize,
    m: *const u8,
    m_len: usize,
    pk: *const u8,
  ) -> c_int;

  #[cfg(feature = "shake")]
  pub fn pqmagic_slh_dsa_shake_256s_simple_std_sign(
    sm: *mut u8,
    sm_len: *mut usize,
    m: *const u8,
    m_len: usize,
    sk: *const u8,
  ) -> c_int;

  #[cfg(feature = "shake")]
  pub fn pqmagic_slh_dsa_shake_256s_simple_std_sign_open(
    m: *mut u8,
    m_len: *mut usize,
    sm: *const u8,
    sm_len: usize,
    pk: *const u8,
  ) -> c_int;

  #[cfg(feature = "sm3")]
  pub fn pqmagic_slh_dsa_sm3_128f_simple_std_sign_keypair(pk: *mut u8, sk: *mut u8) -> c_int;

  #[cfg(feature = "sm3")]
  pub fn pqmagic_slh_dsa_sm3_128f_simple_std_sign_signature(
    sm: *mut u8,
    sm_len: *mut usize,
    m: *const u8,
    m_len: usize,
    sk: *const u8,
  ) -> c_int;

  #[cfg(feature = "sm3")]
  pub fn pqmagic_slh_dsa_sm3_128f_simple_std_sign_verify(
    sm: *const u8,
    sm_len: usize,
    m: *const u8,
    m_len: usize,
    pk: *const u8,
  ) -> c_int;

  #[cfg(feature = "sm3")]
  pub fn pqmagic_slh_dsa_sm3_128f_simple_std_sign(
    sm: *mut u8,
    sm_len: *mut usize,
    m: *const u8,
    m_len: usize,
    sk: *const u8,
  ) -> c_int;

  #[cfg(feature = "sm3")]
  pub fn pqmagic_slh_dsa_sm3_128f_simple_std_sign_open(
    m: *mut u8,
    m_len: *mut usize,
    sm: *const u8,
    sm_len: usize,
    pk: *const u8,
  ) -> c_int;

  #[cfg(feature = "sm3")]
  pub fn pqmagic_slh_dsa_sm3_128s_simple_std_sign_keypair(pk: *mut u8, sk: *mut u8) -> c_int;

  #[cfg(feature = "sm3")]
  pub fn pqmagic_slh_dsa_sm3_128s_simple_std_sign_signature(
    sm: *mut u8,
    sm_len: *mut usize,
    m: *const u8,
    m_len: usize,
    sk: *const u8,
  ) -> c_int;

  #[cfg(feature = "sm3")]
  pub fn pqmagic_slh_dsa_sm3_128s_simple_std_sign_verify(
    sm: *const u8,
    sm_len: usize,
    m: *const u8,
    m_len: usize,
    pk: *const u8,
  ) -> c_int;

  #[cfg(feature = "sm3")]
  pub fn pqmagic_slh_dsa_sm3_128s_simple_std_sign(
    sm: *mut u8,
    sm_len: *mut usize,
    m: *const u8,
    m_len: usize,
    sk: *const u8,
  ) -> c_int;

  #[cfg(feature = "sm3")]
  pub fn pqmagic_slh_dsa_sm3_128s_simple_std_sign_open(
    m: *mut u8,
    m_len: *mut usize,
    sm: *const u8,
    sm_len: usize,
    pk: *const u8,
  ) -> c_int;
}
