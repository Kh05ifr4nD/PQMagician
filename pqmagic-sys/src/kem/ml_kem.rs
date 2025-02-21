use ::core::ffi::c_int;

pub const ML_KEM_512_PUBLICKEYBYTES: usize = 800;
pub const ML_KEM_512_SECRETKEYBYTES: usize = 1632;
pub const ML_KEM_512_CIPHERTEXTBYTES: usize = 768;
pub const ML_KEM_512_SSBYTES: usize = 32;
pub const ML_KEM_768_PUBLICKEYBYTES: usize = 1184;
pub const ML_KEM_768_SECRETKEYBYTES: usize = 2400;
pub const ML_KEM_768_CIPHERTEXTBYTES: usize = 1088;
pub const ML_KEM_768_SSBYTES: usize = 32;
pub const ML_KEM_1024_PUBLICKEYBYTES: usize = 1568;
pub const ML_KEM_1024_SECRETKEYBYTES: usize = 3168;
pub const ML_KEM_1024_CIPHERTEXTBYTES: usize = 1568;
pub const ML_KEM_1024_SSBYTES: usize = 32;

unsafe extern "C" {
  pub fn pqmagic_ml_kem_512_std_keypair_internal(pk: *mut u8, sk: *mut u8, coins: *mut u8)
  -> c_int;

  pub fn pqmagic_ml_kem_512_std_keypair(pk: *mut u8, sk: *mut u8) -> c_int;

  pub fn pqmagic_ml_kem_512_std_enc_internal(
    ct: *mut u8,
    ss: *mut u8,
    pk: *const u8,
    coins: *const u8,
  ) -> c_int;

  pub fn pqmagic_ml_kem_512_std_enc(ct: *mut u8, ss: *mut u8, pk: *const u8) -> c_int;

  pub fn pqmagic_ml_kem_512_std_dec(ss: *mut u8, ct: *const u8, sk: *const u8) -> c_int;

  pub fn pqmagic_ml_kem_768_std_keypair_internal(pk: *mut u8, sk: *mut u8, coins: *mut u8)
  -> c_int;

  pub fn pqmagic_ml_kem_768_std_keypair(pk: *mut u8, sk: *mut u8) -> c_int;

  pub fn pqmagic_ml_kem_768_std_enc_internal(
    ct: *mut u8,
    ss: *mut u8,
    pk: *const u8,
    coins: *const u8,
  ) -> c_int;

  pub fn pqmagic_ml_kem_768_std_enc(ct: *mut u8, ss: *mut u8, pk: *const u8) -> c_int;

  pub fn pqmagic_ml_kem_768_std_dec(ss: *mut u8, ct: *const u8, sk: *const u8) -> c_int;

  pub fn pqmagic_ml_kem_1024_std_keypair_internal(
    pk: *mut u8,
    sk: *mut u8,
    coins: *mut u8,
  ) -> c_int;

  pub fn pqmagic_ml_kem_1024_std_keypair(pk: *mut u8, sk: *mut u8) -> c_int;

  pub fn pqmagic_ml_kem_1024_std_enc_internal(
    ct: *mut u8,
    ss: *mut u8,
    pk: *const u8,
    coins: *const u8,
  ) -> c_int;

  pub fn pqmagic_ml_kem_1024_std_enc(ct: *mut u8, ss: *mut u8, pk: *const u8) -> c_int;

  pub fn pqmagic_ml_kem_1024_std_dec(ss: *mut u8, ct: *const u8, sk: *const u8) -> c_int;
}
