use ::core::ffi::c_int;

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
  pub fn pqmagic_aigis_sig1_std_keypair(pk: *mut u8, sk: *mut u8) -> c_int;

  pub fn pqmagic_aigis_sig1_std_signature(
    sig: *mut u8,
    sig_len: *mut usize,
    m: *const u8,
    m_len: usize,
    ctx: *const u8,
    ctx_len: usize,
    sk: *const u8,
  ) -> c_int;

  pub fn pqmagic_aigis_sig1_std_verify(
    sig: *const u8,
    sig_len: usize,
    m: *const u8,
    m_len: usize,
    ctx: *const u8,
    ctx_len: usize,
    pk: *const u8,
  ) -> c_int;

  pub fn pqmagic_aigis_sig2_std_keypair(pk: *mut u8, sk: *mut u8) -> c_int;

  pub fn pqmagic_aigis_sig2_std_signature(
    sig: *mut u8,
    sig_len: *mut usize,
    m: *const u8,
    m_len: usize,
    ctx: *const u8,
    ctx_len: usize,
    sk: *const u8,
  ) -> c_int;

  pub fn pqmagic_aigis_sig2_std_verify(
    sig: *const u8,
    sig_len: usize,
    m: *const u8,
    m_len: usize,
    ctx: *const u8,
    ctx_len: usize,
    pk: *const u8,
  ) -> c_int;

  pub fn pqmagic_aigis_sig3_std_keypair(pk: *mut u8, sk: *mut u8) -> c_int;

  pub fn pqmagic_aigis_sig3_std_signature(
    sig: *mut u8,
    sig_len: *mut usize,
    m: *const u8,
    m_len: usize,
    ctx: *const u8,
    ctx_len: usize,
    sk: *const u8,
  ) -> c_int;

  pub fn pqmagic_aigis_sig3_std_verify(
    sig: *const u8,
    sig_len: usize,
    m: *const u8,
    m_len: usize,
    ctx: *const u8,
    ctx_len: usize,
    pk: *const u8,
  ) -> c_int;
}
