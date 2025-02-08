use ::core::ffi::c_int;

pub const KYBER512_PUBLICKEYBYTES: usize = 800;
pub const KYBER512_SECRETKEYBYTES: usize = 1632;
pub const KYBER512_CIPHERTEXTBYTES: usize = 768;
pub const KYBER512_SSBYTES: usize = 32;
pub const KYBER768_PUBLICKEYBYTES: usize = 1184;
pub const KYBER768_SECRETKEYBYTES: usize = 2400;
pub const KYBER768_CIPHERTEXTBYTES: usize = 1088;
pub const KYBER768_SSBYTES: usize = 32;
pub const KYBER1024_PUBLICKEYBYTES: usize = 1568;
pub const KYBER1024_SECRETKEYBYTES: usize = 3168;
pub const KYBER1024_CIPHERTEXTBYTES: usize = 1568;
pub const KYBER1024_SSBYTES: usize = 32;

extern "C" {
  pub fn pqmagic_kyber512_std_keypair(pk: *mut u8, sk: *mut u8) -> c_int;

  pub fn pqmagic_kyber512_std_enc(ct: *mut u8, ss: *mut u8, pk: *const u8) -> c_int;

  pub fn pqmagic_kyber512_std_dec(ss: *mut u8, ct: *const u8, sk: *const u8) -> c_int;

  pub fn pqmagic_kyber768_std_keypair(pk: *mut u8, sk: *mut u8) -> c_int;

  pub fn pqmagic_kyber768_std_enc(ct: *mut u8, ss: *mut u8, pk: *const u8) -> c_int;

  pub fn pqmagic_kyber768_std_dec(ss: *mut u8, ct: *const u8, sk: *const u8) -> c_int;

  pub fn pqmagic_kyber1024_std_keypair(pk: *mut u8, sk: *mut u8) -> c_int;

  pub fn pqmagic_kyber1024_std_enc(ct: *mut u8, ss: *mut u8, pk: *const u8) -> c_int;

  pub fn pqmagic_kyber1024_std_dec(ss: *mut u8, ct: *const u8, sk: *const u8) -> c_int;
}
