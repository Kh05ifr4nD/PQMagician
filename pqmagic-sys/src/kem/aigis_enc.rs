use ::core::ffi::c_int;

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

extern "C" {
  pub fn pqmagic_aigis_enc_1_std_keypair(pk: *mut u8, sk: *mut u8) -> c_int;

  pub fn pqmagic_aigis_enc_1_std_enc(ct: *mut u8, ss: *mut u8, pk: *const u8) -> c_int;

  pub fn pqmagic_aigis_enc_1_std_dec(ss: *mut u8, ct: *const u8, sk: *const u8) -> c_int;

  pub fn pqmagic_aigis_enc_2_std_keypair(pk: *mut u8, sk: *mut u8) -> c_int;

  pub fn pqmagic_aigis_enc_2_std_enc(ct: *mut u8, ss: *mut u8, pk: *const u8) -> c_int;

  pub fn pqmagic_aigis_enc_2_std_dec(ss: *mut u8, ct: *const u8, sk: *const u8) -> c_int;

  pub fn pqmagic_aigis_enc_3_std_keypair(pk: *mut u8, sk: *mut u8) -> c_int;

  pub fn pqmagic_aigis_enc_3_std_enc(ct: *mut u8, ss: *mut u8, pk: *const u8) -> c_int;

  pub fn pqmagic_aigis_enc_3_std_dec(ss: *mut u8, ct: *const u8, sk: *const u8) -> c_int;

  pub fn pqmagic_aigis_enc_4_std_keypair(pk: *mut u8, sk: *mut u8) -> c_int;

  pub fn pqmagic_aigis_enc_4_std_enc(ct: *mut u8, ss: *mut u8, pk: *const u8) -> c_int;

  pub fn pqmagic_aigis_enc_4_std_dec(ss: *mut u8, ct: *const u8, sk: *const u8) -> c_int;
}
