use ::core::ffi::c_int;

pub const ML_DSA_44_PUBLICKEYBYTES: usize = 1312;
pub const ML_DSA_44_SECRETKEYBYTES: usize = 2560;
pub const ML_DSA_44_SIGBYTES: usize = 2420;
pub const ML_DSA_65_PUBLICKEYBYTES: usize = 1952;
pub const ML_DSA_65_SECRETKEYBYTES: usize = 4032;
pub const ML_DSA_65_SIGBYTES: usize = 3309;
pub const ML_DSA_87_PUBLICKEYBYTES: usize = 2592;
pub const ML_DSA_87_SECRETKEYBYTES: usize = 4896;
pub const ML_DSA_87_SIGBYTES: usize = 4627;

extern "C" {
  pub fn pqmagic_ml_dsa_44_std_keypair_internal(
    pk: *mut u8,
    sk: *mut u8,
    coins: *const u8,
  ) -> c_int;

  pub fn pqmagic_ml_dsa_44_std_keypair(pk: *mut u8, sk: *mut u8) -> c_int;

  pub fn pqmagic_ml_dsa_44_std_signature_internal(
    sig: *mut u8,
    sig_len: *mut usize,
    m: *const u8,
    m_len: usize,
    coins: *const u8,
    sk: *const u8,
  ) -> c_int;

  pub fn pqmagic_ml_dsa_44_std_signature(
    sig: *mut u8,
    sig_len: *mut usize,
    m: *const u8,
    m_len: usize,
    ctx: *const u8,
    ctx_len: usize,
    sk: *const u8,
  ) -> c_int;

  pub fn pqmagic_ml_dsa_44_std_verify_internal(
    sig: *const u8,
    sig_len: usize,
    m: *const u8,
    m_len: usize,
    pk: *const u8,
  ) -> c_int;

  pub fn pqmagic_ml_dsa_44_std_verify(
    sig: *const u8,
    sig_len: usize,
    m: *const u8,
    m_len: usize,
    ctx: *const u8,
    ctx_len: usize,
    pk: *const u8,
  ) -> c_int;

  pub fn pqmagic_ml_dsa_44_std(
    sm: *mut u8,
    sm_len: *mut usize,
    m: *const u8,
    m_len: usize,
    ctx: *const u8,
    ctx_len: usize,
    sk: *const u8,
  ) -> c_int;

  pub fn pqmagic_ml_dsa_44_std_open(
    m: *mut u8,
    m_len: *mut usize,
    sm: *const u8,
    sm_len: usize,
    ctx: *const u8,
    ctx_len: usize,
    pk: *const u8,
  ) -> c_int;

  pub fn pqmagic_ml_dsa_65_std_keypair_internal(
    pk: *mut u8,
    sk: *mut u8,
    coins: *const u8,
  ) -> c_int;

  pub fn pqmagic_ml_dsa_65_std_keypair(pk: *mut u8, sk: *mut u8) -> c_int;

  pub fn pqmagic_ml_dsa_65_std_signature_internal(
    sig: *mut u8,
    sig_len: *mut usize,
    m: *const u8,
    m_len: usize,
    coins: *const u8,
    sk: *const u8,
  ) -> c_int;

  pub fn pqmagic_ml_dsa_65_std_signature(
    sig: *mut u8,
    sig_len: *mut usize,
    m: *const u8,
    m_len: usize,
    ctx: *const u8,
    ctx_len: usize,
    sk: *const u8,
  ) -> c_int;

  pub fn pqmagic_ml_dsa_65_std_verify_internal(
    sig: *const u8,
    sig_len: usize,
    m: *const u8,
    m_len: usize,
    pk: *const u8,
  ) -> c_int;

  pub fn pqmagic_ml_dsa_65_std_verify(
    sig: *const u8,
    sig_len: usize,
    m: *const u8,
    m_len: usize,
    ctx: *const u8,
    ctx_len: usize,
    pk: *const u8,
  ) -> c_int;

  pub fn pqmagic_ml_dsa_65_std(
    sm: *mut u8,
    sm_len: *mut usize,
    m: *const u8,
    m_len: usize,
    ctx: *const u8,
    ctx_len: usize,
    sk: *const u8,
  ) -> c_int;

  pub fn pqmagic_ml_dsa_65_std_open(
    m: *mut u8,
    m_len: *mut usize,
    sm: *const u8,
    sm_len: usize,
    ctx: *const u8,
    ctx_len: usize,
    pk: *const u8,
  ) -> c_int;

  pub fn pqmagic_ml_dsa_87_std_keypair_internal(
    pk: *mut u8,
    sk: *mut u8,
    coins: *const u8,
  ) -> c_int;

  pub fn pqmagic_ml_dsa_87_std_keypair(pk: *mut u8, sk: *mut u8) -> c_int;

  pub fn pqmagic_ml_dsa_87_std_signature_internal(
    sig: *mut u8,
    sig_len: *mut usize,
    m: *const u8,
    m_len: usize,
    coins: *const u8,
    sk: *const u8,
  ) -> c_int;

  pub fn pqmagic_ml_dsa_87_std_signature(
    sig: *mut u8,
    sig_len: *mut usize,
    m: *const u8,
    m_len: usize,
    ctx: *const u8,
    ctx_len: usize,
    sk: *const u8,
  ) -> c_int;

  pub fn pqmagic_ml_dsa_87_std_verify_internal(
    sig: *const u8,
    sig_len: usize,
    m: *const u8,
    m_len: usize,
    pk: *const u8,
  ) -> c_int;

  pub fn pqmagic_ml_dsa_87_std_verify(
    sig: *const u8,
    sig_len: usize,
    m: *const u8,
    m_len: usize,
    ctx: *const u8,
    ctx_len: usize,
    pk: *const u8,
  ) -> c_int;

  pub fn pqmagic_ml_dsa_87_std(
    sm: *mut u8,
    sm_len: *mut usize,
    m: *const u8,
    m_len: usize,
    ctx: *const u8,
    ctx_len: usize,
    sk: *const u8,
  ) -> c_int;

  pub fn pqmagic_ml_dsa_87_std_open(
    m: *mut u8,
    m_len: *mut usize,
    sm: *const u8,
    sm_len: usize,
    ctx: *const u8,
    ctx_len: usize,
    pk: *const u8,
  ) -> c_int;
}
