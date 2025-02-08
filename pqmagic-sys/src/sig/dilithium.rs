use ::core::ffi::c_int;

pub const DILITHIUM2_PUBLICKEYBYTES: usize = 1312;
pub const DILITHIUM2_SECRETKEYBYTES: usize = 2528;
pub const DILITHIUM2_SIGBYTES: usize = 2420;
pub const DILITHIUM3_PUBLICKEYBYTES: usize = 1952;
pub const DILITHIUM3_SECRETKEYBYTES: usize = 4000;
pub const DILITHIUM3_SIGBYTES: usize = 3293;
pub const DILITHIUM5_PUBLICKEYBYTES: usize = 2592;
pub const DILITHIUM5_SECRETKEYBYTES: usize = 4864;
pub const DILITHIUM5_SIGBYTES: usize = 4595;

extern "C" {
  pub fn pqmagic_dilithium2_std_keypair(pk: *mut u8, sk: *mut u8) -> c_int;

  pub fn pqmagic_dilithium2_std_signature(
    sm: *mut u8,
    sm_len: *mut usize,
    m: *const u8,
    m_len: usize,
    sk: *const u8,
  ) -> c_int;

  pub fn pqmagic_dilithium2_std_verify(
    sm: *const u8,
    sm_len: usize,
    m: *const u8,
    m_len: usize,
    pk: *const u8,
  ) -> c_int;

  pub fn pqmagic_dilithium2_std(
    sm: *mut u8,
    sm_len: *mut usize,
    m: *const u8,
    m_len: usize,
    sk: *const u8,
  ) -> c_int;

  pub fn pqmagic_dilithium2_std_open(
    m: *mut u8,
    m_len: *mut usize,
    sm: *const u8,
    sm_len: usize,
    pk: *const u8,
  ) -> c_int;

  pub fn pqmagic_dilithium3_std_keypair(pk: *mut u8, sk: *mut u8) -> c_int;

  pub fn pqmagic_dilithium3_std_signature(
    sm: *mut u8,
    sm_len: *mut usize,
    m: *const u8,
    m_len: usize,
    sk: *const u8,
  ) -> c_int;

  pub fn pqmagic_dilithium3_std_verify(
    sm: *const u8,
    sm_len: usize,
    m: *const u8,
    m_len: usize,
    pk: *const u8,
  ) -> c_int;

  pub fn pqmagic_dilithium3_std(
    sm: *mut u8,
    sm_len: *mut usize,
    m: *const u8,
    m_len: usize,
    sk: *const u8,
  ) -> c_int;

  pub fn pqmagic_dilithium3_std_open(
    m: *mut u8,
    m_len: *mut usize,
    sm: *const u8,
    sm_len: usize,
    pk: *const u8,
  ) -> c_int;

  pub fn pqmagic_dilithium5_std_keypair(pk: *mut u8, sk: *mut u8) -> c_int;

  pub fn pqmagic_dilithium5_std_signature(
    sm: *mut u8,
    sm_len: *mut usize,
    m: *const u8,
    m_len: usize,
    sk: *const u8,
  ) -> c_int;

  pub fn pqmagic_dilithium5_std_verify(
    sm: *const u8,
    sm_len: usize,
    m: *const u8,
    m_len: usize,
    pk: *const u8,
  ) -> c_int;

  pub fn pqmagic_dilithium5_std(
    sm: *mut u8,
    sm_len: *mut usize,
    m: *const u8,
    m_len: usize,
    sk: *const u8,
  ) -> c_int;

  pub fn pqmagic_dilithium5_std_open(
    m: *mut u8,
    m_len: *mut usize,
    sm: *const u8,
    sm_len: usize,
    pk: *const u8,
  ) -> c_int;
}
