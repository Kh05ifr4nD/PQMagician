#![no_std]

unsafe extern "C" {
  pub fn randombytes(out: *mut u8, out_len: usize);
}

#[allow(non_upper_case_globals)]
#[cfg(any(feature = "aigis_enc", feature = "ml_kem", feature = "kyber"))]
pub mod kem {
  #[cfg(feature = "aigis_enc")]
  pub mod aigis_enc {
    use ::libc::c_int;
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
    unsafe extern "C" {
      pub fn pqmagic_aigis_enc_1_std_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_aigis_enc_1_std_enc(ct: *mut u8, ss: *mut u8, pk: *const u8) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_aigis_enc_1_std_dec(ss: *mut u8, ct: *const u8, sk: *const u8) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_aigis_enc_2_std_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_aigis_enc_2_std_enc(ct: *mut u8, ss: *mut u8, pk: *const u8) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_aigis_enc_2_std_dec(ss: *mut u8, ct: *const u8, sk: *const u8) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_aigis_enc_3_std_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_aigis_enc_3_std_enc(ct: *mut u8, ss: *mut u8, pk: *const u8) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_aigis_enc_3_std_dec(ss: *mut u8, ct: *const u8, sk: *const u8) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_aigis_enc_4_std_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_aigis_enc_4_std_enc(ct: *mut u8, ss: *mut u8, pk: *const u8) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_aigis_enc_4_std_dec(ss: *mut u8, ct: *const u8, sk: *const u8) -> c_int;
    }
  }
  #[cfg(feature = "kyber")]
  pub mod kyber {
    use ::libc::c_int;
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
    unsafe extern "C" {
      pub fn pqmagic_kyber512_std_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_kyber512_std_enc(ct: *mut u8, ss: *mut u8, pk: *const u8) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_kyber512_std_dec(ss: *mut u8, ct: *const u8, sk: *const u8) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_kyber768_std_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_kyber768_std_enc(ct: *mut u8, ss: *mut u8, pk: *const u8) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_kyber768_std_dec(ss: *mut u8, ct: *const u8, sk: *const u8) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_kyber1024_std_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_kyber1024_std_enc(ct: *mut u8, ss: *mut u8, pk: *const u8) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_kyber1024_std_dec(ss: *mut u8, ct: *const u8, sk: *const u8) -> c_int;
    }
  }
  #[cfg(feature = "ml_kem")]
  pub mod ml_kem {
    use ::libc::c_int;
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
      pub fn pqmagic_ml_kem_512_std_keypair_internal(
        pk: *mut u8,
        sk: *mut u8,
        coins: *mut u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_ml_kem_512_std_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_ml_kem_512_std_enc_internal(
        ct: *mut u8,
        ss: *mut u8,
        pk: *const u8,
        coins: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_ml_kem_512_std_enc(ct: *mut u8, ss: *mut u8, pk: *const u8) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_ml_kem_512_std_dec(ss: *mut u8, ct: *const u8, sk: *const u8) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_ml_kem_768_std_keypair_internal(
        pk: *mut u8,
        sk: *mut u8,
        coins: *mut u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_ml_kem_768_std_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_ml_kem_768_std_enc_internal(
        ct: *mut u8,
        ss: *mut u8,
        pk: *const u8,
        coins: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_ml_kem_768_std_enc(ct: *mut u8, ss: *mut u8, pk: *const u8) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_ml_kem_768_std_dec(ss: *mut u8, ct: *const u8, sk: *const u8) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_ml_kem_1024_std_keypair_internal(
        pk: *mut u8,
        sk: *mut u8,
        coins: *mut u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_ml_kem_1024_std_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_ml_kem_1024_std_enc_internal(
        ct: *mut u8,
        ss: *mut u8,
        pk: *const u8,
        coins: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_ml_kem_1024_std_enc(ct: *mut u8, ss: *mut u8, pk: *const u8) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_ml_kem_1024_std_dec(ss: *mut u8, ct: *const u8, sk: *const u8) -> c_int;
    }
  }
}
#[allow(non_upper_case_globals)]
#[cfg(any(
  feature = "aigis_sig",
  feature = "dilithium",
  feature = "ml_dsa",
  feature = "slh_dsa",
  feature = "sphincs_a"
))]
pub mod sig {
  #[cfg(feature = "aigis_sig")]
  pub mod aigis_sig {
    use ::libc::c_int;
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
    }
    unsafe extern "C" {
      pub fn pqmagic_aigis_sig1_std_signature(
        sig: *mut u8,
        sig_len: *mut usize,
        m: *const u8,
        m_len: usize,
        ctx: *const u8,
        ctx_len: usize,
        sk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_aigis_sig1_std_verify(
        sig: *const u8,
        sig_len: usize,
        m: *const u8,
        m_len: usize,
        ctx: *const u8,
        ctx_len: usize,
        pk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_aigis_sig2_std_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_aigis_sig2_std_signature(
        sig: *mut u8,
        sig_len: *mut usize,
        m: *const u8,
        m_len: usize,
        ctx: *const u8,
        ctx_len: usize,
        sk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_aigis_sig2_std_verify(
        sig: *const u8,
        sig_len: usize,
        m: *const u8,
        m_len: usize,
        ctx: *const u8,
        ctx_len: usize,
        pk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_aigis_sig3_std_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_aigis_sig3_std_signature(
        sig: *mut u8,
        sig_len: *mut usize,
        m: *const u8,
        m_len: usize,
        ctx: *const u8,
        ctx_len: usize,
        sk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
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
  }
  #[cfg(feature = "dilithium")]
  pub mod dilithium {
    use ::libc::c_int;
    pub const DILITHIUM2_PUBLICKEYBYTES: usize = 1312;
    pub const DILITHIUM2_SECRETKEYBYTES: usize = 2528;
    pub const DILITHIUM2_SIGBYTES: usize = 2420;
    pub const DILITHIUM3_PUBLICKEYBYTES: usize = 1952;
    pub const DILITHIUM3_SECRETKEYBYTES: usize = 4000;
    pub const DILITHIUM3_SIGBYTES: usize = 3293;
    pub const DILITHIUM5_PUBLICKEYBYTES: usize = 2592;
    pub const DILITHIUM5_SECRETKEYBYTES: usize = 4864;
    pub const DILITHIUM5_SIGBYTES: usize = 4595;
    unsafe extern "C" {
      pub fn pqmagic_dilithium2_std_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_dilithium2_std_signature(
        sm: *mut u8,
        sm_len: *mut usize,
        m: *const u8,
        m_len: usize,
        sk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_dilithium2_std_verify(
        sm: *const u8,
        sm_len: usize,
        m: *const u8,
        m_len: usize,
        pk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_dilithium2_std(
        sm: *mut u8,
        sm_len: *mut usize,
        m: *const u8,
        m_len: usize,
        sk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_dilithium2_std_open(
        m: *mut u8,
        m_len: *mut usize,
        sm: *const u8,
        sm_len: usize,
        pk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_dilithium3_std_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_dilithium3_std_signature(
        sm: *mut u8,
        sm_len: *mut usize,
        m: *const u8,
        m_len: usize,
        sk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_dilithium3_std_verify(
        sm: *const u8,
        sm_len: usize,
        m: *const u8,
        m_len: usize,
        pk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_dilithium3_std(
        sm: *mut u8,
        sm_len: *mut usize,
        m: *const u8,
        m_len: usize,
        sk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_dilithium3_std_open(
        m: *mut u8,
        m_len: *mut usize,
        sm: *const u8,
        sm_len: usize,
        pk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_dilithium5_std_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_dilithium5_std_signature(
        sm: *mut u8,
        sm_len: *mut usize,
        m: *const u8,
        m_len: usize,
        sk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_dilithium5_std_verify(
        sm: *const u8,
        sm_len: usize,
        m: *const u8,
        m_len: usize,
        pk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_dilithium5_std(
        sm: *mut u8,
        sm_len: *mut usize,
        m: *const u8,
        m_len: usize,
        sk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_dilithium5_std_open(
        m: *mut u8,
        m_len: *mut usize,
        sm: *const u8,
        sm_len: usize,
        pk: *const u8,
      ) -> c_int;
    }
  }
  #[cfg(feature = "ml_dsa")]
  pub mod ml_dsa {
    use ::libc::c_int;
    pub const ML_DSA_44_PUBLICKEYBYTES: usize = 1312;
    pub const ML_DSA_44_SECRETKEYBYTES: usize = 2560;
    pub const ML_DSA_44_SIGBYTES: usize = 2420;
    pub const ML_DSA_65_PUBLICKEYBYTES: usize = 1952;
    pub const ML_DSA_65_SECRETKEYBYTES: usize = 4032;
    pub const ML_DSA_65_SIGBYTES: usize = 3309;
    pub const ML_DSA_87_PUBLICKEYBYTES: usize = 2592;
    pub const ML_DSA_87_SECRETKEYBYTES: usize = 4896;
    pub const ML_DSA_87_SIGBYTES: usize = 4627;
    unsafe extern "C" {
      pub fn pqmagic_ml_dsa_44_std_keypair_internal(
        pk: *mut u8,
        sk: *mut u8,
        coins: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_ml_dsa_44_std_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_ml_dsa_44_std_signature_internal(
        sig: *mut u8,
        sig_len: *mut usize,
        m: *const u8,
        m_len: usize,
        coins: *const u8,
        sk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_ml_dsa_44_std_signature(
        sig: *mut u8,
        sig_len: *mut usize,
        m: *const u8,
        m_len: usize,
        ctx: *const u8,
        ctx_len: usize,
        sk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_ml_dsa_44_std_verify_internal(
        sig: *const u8,
        sig_len: usize,
        m: *const u8,
        m_len: usize,
        pk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_ml_dsa_44_std_verify(
        sig: *const u8,
        sig_len: usize,
        m: *const u8,
        m_len: usize,
        ctx: *const u8,
        ctx_len: usize,
        pk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_ml_dsa_44_std(
        sm: *mut u8,
        sm_len: *mut usize,
        m: *const u8,
        m_len: usize,
        ctx: *const u8,
        ctx_len: usize,
        sk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_ml_dsa_44_std_open(
        m: *mut u8,
        m_len: *mut usize,
        sm: *const u8,
        sm_len: usize,
        ctx: *const u8,
        ctx_len: usize,
        pk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_ml_dsa_65_std_keypair_internal(
        pk: *mut u8,
        sk: *mut u8,
        coins: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_ml_dsa_65_std_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_ml_dsa_65_std_signature_internal(
        sig: *mut u8,
        sig_len: *mut usize,
        m: *const u8,
        m_len: usize,
        coins: *const u8,
        sk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_ml_dsa_65_std_signature(
        sig: *mut u8,
        sig_len: *mut usize,
        m: *const u8,
        m_len: usize,
        ctx: *const u8,
        ctx_len: usize,
        sk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_ml_dsa_65_std_verify_internal(
        sig: *const u8,
        sig_len: usize,
        m: *const u8,
        m_len: usize,
        pk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_ml_dsa_65_std_verify(
        sig: *const u8,
        sig_len: usize,
        m: *const u8,
        m_len: usize,
        ctx: *const u8,
        ctx_len: usize,
        pk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_ml_dsa_65_std(
        sm: *mut u8,
        sm_len: *mut usize,
        m: *const u8,
        m_len: usize,
        ctx: *const u8,
        ctx_len: usize,
        sk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_ml_dsa_65_std_open(
        m: *mut u8,
        m_len: *mut usize,
        sm: *const u8,
        sm_len: usize,
        ctx: *const u8,
        ctx_len: usize,
        pk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_ml_dsa_87_std_keypair_internal(
        pk: *mut u8,
        sk: *mut u8,
        coins: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_ml_dsa_87_std_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_ml_dsa_87_std_signature_internal(
        sig: *mut u8,
        sig_len: *mut usize,
        m: *const u8,
        m_len: usize,
        coins: *const u8,
        sk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_ml_dsa_87_std_signature(
        sig: *mut u8,
        sig_len: *mut usize,
        m: *const u8,
        m_len: usize,
        ctx: *const u8,
        ctx_len: usize,
        sk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_ml_dsa_87_std_verify_internal(
        sig: *const u8,
        sig_len: usize,
        m: *const u8,
        m_len: usize,
        pk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_ml_dsa_87_std_verify(
        sig: *const u8,
        sig_len: usize,
        m: *const u8,
        m_len: usize,
        ctx: *const u8,
        ctx_len: usize,
        pk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_ml_dsa_87_std(
        sm: *mut u8,
        sm_len: *mut usize,
        m: *const u8,
        m_len: usize,
        ctx: *const u8,
        ctx_len: usize,
        sk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
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
  }
  #[cfg(feature = "slh_dsa")]
  pub mod slh_dsa {
    use ::libc::c_int;
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
      pub fn pqmagic_slh_dsa_sha2_128f_simple_std_sign_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_slh_dsa_sha2_128f_simple_std_sign_signature(
        sm: *mut u8,
        sm_len: *mut usize,
        m: *const u8,
        m_len: usize,
        sk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_slh_dsa_sha2_128f_simple_std_sign_verify(
        sm: *const u8,
        sm_len: usize,
        m: *const u8,
        m_len: usize,
        pk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_slh_dsa_sha2_128f_simple_std_sign(
        sm: *mut u8,
        sm_len: *mut usize,
        m: *const u8,
        m_len: usize,
        sk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_slh_dsa_sha2_128f_simple_std_sign_open(
        m: *mut u8,
        m_len: *mut usize,
        sm: *const u8,
        sm_len: usize,
        pk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_slh_dsa_sha2_128s_simple_std_sign_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_slh_dsa_sha2_128s_simple_std_sign_signature(
        sm: *mut u8,
        sm_len: *mut usize,
        m: *const u8,
        m_len: usize,
        sk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_slh_dsa_sha2_128s_simple_std_sign_verify(
        sm: *const u8,
        sm_len: usize,
        m: *const u8,
        m_len: usize,
        pk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_slh_dsa_sha2_128s_simple_std_sign(
        sm: *mut u8,
        sm_len: *mut usize,
        m: *const u8,
        m_len: usize,
        sk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_slh_dsa_sha2_128s_simple_std_sign_open(
        m: *mut u8,
        m_len: *mut usize,
        sm: *const u8,
        sm_len: usize,
        pk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_slh_dsa_sha2_192f_simple_std_sign_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_slh_dsa_sha2_192f_simple_std_sign_signature(
        sm: *mut u8,
        sm_len: *mut usize,
        m: *const u8,
        m_len: usize,
        sk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_slh_dsa_sha2_192f_simple_std_sign_verify(
        sm: *const u8,
        sm_len: usize,
        m: *const u8,
        m_len: usize,
        pk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_slh_dsa_sha2_192f_simple_std_sign(
        sm: *mut u8,
        sm_len: *mut usize,
        m: *const u8,
        m_len: usize,
        sk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_slh_dsa_sha2_192f_simple_std_sign_open(
        m: *mut u8,
        m_len: *mut usize,
        sm: *const u8,
        sm_len: usize,
        pk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_slh_dsa_sha2_192s_simple_std_sign_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_slh_dsa_sha2_192s_simple_std_sign_signature(
        sm: *mut u8,
        sm_len: *mut usize,
        m: *const u8,
        m_len: usize,
        sk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_slh_dsa_sha2_192s_simple_std_sign_verify(
        sm: *const u8,
        sm_len: usize,
        m: *const u8,
        m_len: usize,
        pk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_slh_dsa_sha2_192s_simple_std_sign(
        sm: *mut u8,
        sm_len: *mut usize,
        m: *const u8,
        m_len: usize,
        sk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_slh_dsa_sha2_192s_simple_std_sign_open(
        m: *mut u8,
        m_len: *mut usize,
        sm: *const u8,
        sm_len: usize,
        pk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_slh_dsa_sha2_256f_simple_std_sign_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_slh_dsa_sha2_256f_simple_std_sign_signature(
        sm: *mut u8,
        sm_len: *mut usize,
        m: *const u8,
        m_len: usize,
        sk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_slh_dsa_sha2_256f_simple_std_sign_verify(
        sm: *const u8,
        sm_len: usize,
        m: *const u8,
        m_len: usize,
        pk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_slh_dsa_sha2_256f_simple_std_sign(
        sm: *mut u8,
        sm_len: *mut usize,
        m: *const u8,
        m_len: usize,
        sk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_slh_dsa_sha2_256f_simple_std_sign_open(
        m: *mut u8,
        m_len: *mut usize,
        sm: *const u8,
        sm_len: usize,
        pk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_slh_dsa_sha2_256s_simple_std_sign_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_slh_dsa_sha2_256s_simple_std_sign_signature(
        sm: *mut u8,
        sm_len: *mut usize,
        m: *const u8,
        m_len: usize,
        sk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_slh_dsa_sha2_256s_simple_std_sign_verify(
        sm: *const u8,
        sm_len: usize,
        m: *const u8,
        m_len: usize,
        pk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_slh_dsa_sha2_256s_simple_std_sign(
        sm: *mut u8,
        sm_len: *mut usize,
        m: *const u8,
        m_len: usize,
        sk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_slh_dsa_sha2_256s_simple_std_sign_open(
        m: *mut u8,
        m_len: *mut usize,
        sm: *const u8,
        sm_len: usize,
        pk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_slh_dsa_shake_128f_simple_std_sign_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_slh_dsa_shake_128f_simple_std_sign_signature(
        sm: *mut u8,
        sm_len: *mut usize,
        m: *const u8,
        m_len: usize,
        sk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_slh_dsa_shake_128f_simple_std_sign_verify(
        sm: *const u8,
        sm_len: usize,
        m: *const u8,
        m_len: usize,
        pk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_slh_dsa_shake_128f_simple_std_sign(
        sm: *mut u8,
        sm_len: *mut usize,
        m: *const u8,
        m_len: usize,
        sk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_slh_dsa_shake_128f_simple_std_sign_open(
        m: *mut u8,
        m_len: *mut usize,
        sm: *const u8,
        sm_len: usize,
        pk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_slh_dsa_shake_128s_simple_std_sign_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_slh_dsa_shake_128s_simple_std_sign_signature(
        sm: *mut u8,
        sm_len: *mut usize,
        m: *const u8,
        m_len: usize,
        sk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_slh_dsa_shake_128s_simple_std_sign_verify(
        sm: *const u8,
        sm_len: usize,
        m: *const u8,
        m_len: usize,
        pk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_slh_dsa_shake_128s_simple_std_sign(
        sm: *mut u8,
        sm_len: *mut usize,
        m: *const u8,
        m_len: usize,
        sk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_slh_dsa_shake_128s_simple_std_sign_open(
        m: *mut u8,
        m_len: *mut usize,
        sm: *const u8,
        sm_len: usize,
        pk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_slh_dsa_shake_192f_simple_std_sign_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_slh_dsa_shake_192f_simple_std_sign_signature(
        sm: *mut u8,
        sm_len: *mut usize,
        m: *const u8,
        m_len: usize,
        sk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_slh_dsa_shake_192f_simple_std_sign_verify(
        sm: *const u8,
        sm_len: usize,
        m: *const u8,
        m_len: usize,
        pk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_slh_dsa_shake_192f_simple_std_sign(
        sm: *mut u8,
        sm_len: *mut usize,
        m: *const u8,
        m_len: usize,
        sk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_slh_dsa_shake_192f_simple_std_sign_open(
        m: *mut u8,
        m_len: *mut usize,
        sm: *const u8,
        sm_len: usize,
        pk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_slh_dsa_shake_192s_simple_std_sign_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_slh_dsa_shake_192s_simple_std_sign_signature(
        sm: *mut u8,
        sm_len: *mut usize,
        m: *const u8,
        m_len: usize,
        sk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_slh_dsa_shake_192s_simple_std_sign_verify(
        sm: *const u8,
        sm_len: usize,
        m: *const u8,
        m_len: usize,
        pk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_slh_dsa_shake_192s_simple_std_sign(
        sm: *mut u8,
        sm_len: *mut usize,
        m: *const u8,
        m_len: usize,
        sk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_slh_dsa_shake_192s_simple_std_sign_open(
        m: *mut u8,
        m_len: *mut usize,
        sm: *const u8,
        sm_len: usize,
        pk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_slh_dsa_shake_256f_simple_std_sign_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_slh_dsa_shake_256f_simple_std_sign_signature(
        sm: *mut u8,
        sm_len: *mut usize,
        m: *const u8,
        m_len: usize,
        sk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_slh_dsa_shake_256f_simple_std_sign_verify(
        sm: *const u8,
        sm_len: usize,
        m: *const u8,
        m_len: usize,
        pk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_slh_dsa_shake_256f_simple_std_sign(
        sm: *mut u8,
        sm_len: *mut usize,
        m: *const u8,
        m_len: usize,
        sk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_slh_dsa_shake_256f_simple_std_sign_open(
        m: *mut u8,
        m_len: *mut usize,
        sm: *const u8,
        sm_len: usize,
        pk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_slh_dsa_shake_256s_simple_std_sign_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_slh_dsa_shake_256s_simple_std_sign_signature(
        sm: *mut u8,
        sm_len: *mut usize,
        m: *const u8,
        m_len: usize,
        sk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_slh_dsa_shake_256s_simple_std_sign_verify(
        sm: *const u8,
        sm_len: usize,
        m: *const u8,
        m_len: usize,
        pk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_slh_dsa_shake_256s_simple_std_sign(
        sm: *mut u8,
        sm_len: *mut usize,
        m: *const u8,
        m_len: usize,
        sk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_slh_dsa_shake_256s_simple_std_sign_open(
        m: *mut u8,
        m_len: *mut usize,
        sm: *const u8,
        sm_len: usize,
        pk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_slh_dsa_sm3_128f_simple_std_sign_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_slh_dsa_sm3_128f_simple_std_sign_signature(
        sm: *mut u8,
        sm_len: *mut usize,
        m: *const u8,
        m_len: usize,
        sk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_slh_dsa_sm3_128f_simple_std_sign_verify(
        sm: *const u8,
        sm_len: usize,
        m: *const u8,
        m_len: usize,
        pk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_slh_dsa_sm3_128f_simple_std_sign(
        sm: *mut u8,
        sm_len: *mut usize,
        m: *const u8,
        m_len: usize,
        sk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_slh_dsa_sm3_128f_simple_std_sign_open(
        m: *mut u8,
        m_len: *mut usize,
        sm: *const u8,
        sm_len: usize,
        pk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_slh_dsa_sm3_128s_simple_std_sign_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_slh_dsa_sm3_128s_simple_std_sign_signature(
        sm: *mut u8,
        sm_len: *mut usize,
        m: *const u8,
        m_len: usize,
        sk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_slh_dsa_sm3_128s_simple_std_sign_verify(
        sm: *const u8,
        sm_len: usize,
        m: *const u8,
        m_len: usize,
        pk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_slh_dsa_sm3_128s_simple_std_sign(
        sm: *mut u8,
        sm_len: *mut usize,
        m: *const u8,
        m_len: usize,
        sk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_slh_dsa_sm3_128s_simple_std_sign_open(
        m: *mut u8,
        m_len: *mut usize,
        sm: *const u8,
        sm_len: usize,
        pk: *const u8,
      ) -> c_int;
    }
  }
  #[cfg(feature = "sphincs_a")]
  pub mod sphincs_a {
    use ::libc::c_int;
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
      pub fn pqmagic_sphincs_a_sha2_128f_simple_std_sign_keypair(pk: *mut u8, sk: *mut u8)
        -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_sphincs_a_sha2_128f_simple_std_sign_signature(
        sm: *mut u8,
        sm_len: *mut usize,
        m: *const u8,
        m_len: usize,
        sk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_sphincs_a_sha2_128f_simple_std_sign_verify(
        sm: *const u8,
        sm_len: usize,
        m: *const u8,
        m_len: usize,
        pk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_sphincs_a_sha2_128f_simple_std_sign(
        sm: *mut u8,
        sm_len: *mut usize,
        m: *const u8,
        m_len: usize,
        sk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_sphincs_a_sha2_128f_simple_std_sign_open(
        m: *mut u8,
        m_len: *mut usize,
        sm: *const u8,
        sm_len: usize,
        pk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_sphincs_a_sha2_128s_simple_std_sign_keypair(pk: *mut u8, sk: *mut u8)
        -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_sphincs_a_sha2_128s_simple_std_sign_signature(
        sm: *mut u8,
        sm_len: *mut usize,
        m: *const u8,
        m_len: usize,
        sk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_sphincs_a_sha2_128s_simple_std_sign_verify(
        sm: *const u8,
        sm_len: usize,
        m: *const u8,
        m_len: usize,
        pk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_sphincs_a_sha2_128s_simple_std_sign(
        sm: *mut u8,
        sm_len: *mut usize,
        m: *const u8,
        m_len: usize,
        sk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_sphincs_a_sha2_128s_simple_std_sign_open(
        m: *mut u8,
        m_len: *mut usize,
        sm: *const u8,
        sm_len: usize,
        pk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_sphincs_a_sha2_192f_simple_std_sign_keypair(pk: *mut u8, sk: *mut u8)
        -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_sphincs_a_sha2_192f_simple_std_sign_signature(
        sm: *mut u8,
        sm_len: *mut usize,
        m: *const u8,
        m_len: usize,
        sk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_sphincs_a_sha2_192f_simple_std_sign_verify(
        sm: *const u8,
        sm_len: usize,
        m: *const u8,
        m_len: usize,
        pk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_sphincs_a_sha2_192f_simple_std_sign(
        sm: *mut u8,
        sm_len: *mut usize,
        m: *const u8,
        m_len: usize,
        sk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_sphincs_a_sha2_192f_simple_std_sign_open(
        m: *mut u8,
        m_len: *mut usize,
        sm: *const u8,
        sm_len: usize,
        pk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_sphincs_a_sha2_192s_simple_std_sign_keypair(pk: *mut u8, sk: *mut u8)
        -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_sphincs_a_sha2_192s_simple_std_sign_signature(
        sm: *mut u8,
        sm_len: *mut usize,
        m: *const u8,
        m_len: usize,
        sk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_sphincs_a_sha2_192s_simple_std_sign_verify(
        sm: *const u8,
        sm_len: usize,
        m: *const u8,
        m_len: usize,
        pk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_sphincs_a_sha2_192s_simple_std_sign(
        sm: *mut u8,
        sm_len: *mut usize,
        m: *const u8,
        m_len: usize,
        sk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_sphincs_a_sha2_192s_simple_std_sign_open(
        m: *mut u8,
        m_len: *mut usize,
        sm: *const u8,
        sm_len: usize,
        pk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_sphincs_a_sha2_256f_simple_std_sign_keypair(pk: *mut u8, sk: *mut u8)
        -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_sphincs_a_sha2_256f_simple_std_sign_signature(
        sm: *mut u8,
        sm_len: *mut usize,
        m: *const u8,
        m_len: usize,
        sk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_sphincs_a_sha2_256f_simple_std_sign_verify(
        sm: *const u8,
        sm_len: usize,
        m: *const u8,
        m_len: usize,
        pk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_sphincs_a_sha2_256f_simple_std_sign(
        sm: *mut u8,
        sm_len: *mut usize,
        m: *const u8,
        m_len: usize,
        sk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_sphincs_a_sha2_256f_simple_std_sign_open(
        m: *mut u8,
        m_len: *mut usize,
        sm: *const u8,
        sm_len: usize,
        pk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_sphincs_a_sha2_256s_simple_std_sign_keypair(pk: *mut u8, sk: *mut u8)
        -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_sphincs_a_sha2_256s_simple_std_sign_signature(
        sm: *mut u8,
        sm_len: *mut usize,
        m: *const u8,
        m_len: usize,
        sk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_sphincs_a_sha2_256s_simple_std_sign_verify(
        sm: *const u8,
        sm_len: usize,
        m: *const u8,
        m_len: usize,
        pk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_sphincs_a_sha2_256s_simple_std_sign(
        sm: *mut u8,
        sm_len: *mut usize,
        m: *const u8,
        m_len: usize,
        sk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_sphincs_a_sha2_256s_simple_std_sign_open(
        m: *mut u8,
        m_len: *mut usize,
        sm: *const u8,
        sm_len: usize,
        pk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_sphincs_a_shake_128f_simple_std_sign_keypair(
        pk: *mut u8,
        sk: *mut u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_sphincs_a_shake_128f_simple_std_sign_signature(
        sm: *mut u8,
        sm_len: *mut usize,
        m: *const u8,
        m_len: usize,
        sk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_sphincs_a_shake_128f_simple_std_sign_verify(
        sm: *const u8,
        sm_len: usize,
        m: *const u8,
        m_len: usize,
        pk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_sphincs_a_shake_128f_simple_std_sign(
        sm: *mut u8,
        sm_len: *mut usize,
        m: *const u8,
        m_len: usize,
        sk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_sphincs_a_shake_128f_simple_std_sign_open(
        m: *mut u8,
        m_len: *mut usize,
        sm: *const u8,
        sm_len: usize,
        pk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_sphincs_a_shake_128s_simple_std_sign_keypair(
        pk: *mut u8,
        sk: *mut u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_sphincs_a_shake_128s_simple_std_sign_signature(
        sm: *mut u8,
        sm_len: *mut usize,
        m: *const u8,
        m_len: usize,
        sk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_sphincs_a_shake_128s_simple_std_sign_verify(
        sm: *const u8,
        sm_len: usize,
        m: *const u8,
        m_len: usize,
        pk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_sphincs_a_shake_128s_simple_std_sign(
        sm: *mut u8,
        sm_len: *mut usize,
        m: *const u8,
        m_len: usize,
        sk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_sphincs_a_shake_128s_simple_std_sign_open(
        m: *mut u8,
        m_len: *mut usize,
        sm: *const u8,
        sm_len: usize,
        pk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_sphincs_a_shake_192f_simple_std_sign_keypair(
        pk: *mut u8,
        sk: *mut u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_sphincs_a_shake_192f_simple_std_sign_signature(
        sm: *mut u8,
        sm_len: *mut usize,
        m: *const u8,
        m_len: usize,
        sk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_sphincs_a_shake_192f_simple_std_sign_verify(
        sm: *const u8,
        sm_len: usize,
        m: *const u8,
        m_len: usize,
        pk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_sphincs_a_shake_192f_simple_std_sign(
        sm: *mut u8,
        sm_len: *mut usize,
        m: *const u8,
        m_len: usize,
        sk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_sphincs_a_shake_192f_simple_std_sign_open(
        m: *mut u8,
        m_len: *mut usize,
        sm: *const u8,
        sm_len: usize,
        pk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_sphincs_a_shake_192s_simple_std_sign_keypair(
        pk: *mut u8,
        sk: *mut u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_sphincs_a_shake_192s_simple_std_sign_signature(
        sm: *mut u8,
        sm_len: *mut usize,
        m: *const u8,
        m_len: usize,
        sk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_sphincs_a_shake_192s_simple_std_sign_verify(
        sm: *const u8,
        sm_len: usize,
        m: *const u8,
        m_len: usize,
        pk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_sphincs_a_shake_192s_simple_std_sign(
        sm: *mut u8,
        sm_len: *mut usize,
        m: *const u8,
        m_len: usize,
        sk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_sphincs_a_shake_192s_simple_std_sign_open(
        m: *mut u8,
        m_len: *mut usize,
        sm: *const u8,
        sm_len: usize,
        pk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_sphincs_a_shake_256f_simple_std_sign_keypair(
        pk: *mut u8,
        sk: *mut u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_sphincs_a_shake_256f_simple_std_sign_signature(
        sm: *mut u8,
        sm_len: *mut usize,
        m: *const u8,
        m_len: usize,
        sk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_sphincs_a_shake_256f_simple_std_sign_verify(
        sm: *const u8,
        sm_len: usize,
        m: *const u8,
        m_len: usize,
        pk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_sphincs_a_shake_256f_simple_std_sign(
        sm: *mut u8,
        sm_len: *mut usize,
        m: *const u8,
        m_len: usize,
        sk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_sphincs_a_shake_256f_simple_std_sign_open(
        m: *mut u8,
        m_len: *mut usize,
        sm: *const u8,
        sm_len: usize,
        pk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_sphincs_a_shake_256s_simple_std_sign_keypair(
        pk: *mut u8,
        sk: *mut u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_sphincs_a_shake_256s_simple_std_sign_signature(
        sm: *mut u8,
        sm_len: *mut usize,
        m: *const u8,
        m_len: usize,
        sk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_sphincs_a_shake_256s_simple_std_sign_verify(
        sm: *const u8,
        sm_len: usize,
        m: *const u8,
        m_len: usize,
        pk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_sphincs_a_shake_256s_simple_std_sign(
        sm: *mut u8,
        sm_len: *mut usize,
        m: *const u8,
        m_len: usize,
        sk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_sphincs_a_shake_256s_simple_std_sign_open(
        m: *mut u8,
        m_len: *mut usize,
        sm: *const u8,
        sm_len: usize,
        pk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_sphincs_a_sm3_128f_simple_std_sign_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_sphincs_a_sm3_128f_simple_std_sign_signature(
        sm: *mut u8,
        sm_len: *mut usize,
        m: *const u8,
        m_len: usize,
        sk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_sphincs_a_sm3_128f_simple_std_sign_verify(
        sm: *const u8,
        sm_len: usize,
        m: *const u8,
        m_len: usize,
        pk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_sphincs_a_sm3_128f_simple_std_sign(
        sm: *mut u8,
        sm_len: *mut usize,
        m: *const u8,
        m_len: usize,
        sk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_sphincs_a_sm3_128f_simple_std_sign_open(
        m: *mut u8,
        m_len: *mut usize,
        sm: *const u8,
        sm_len: usize,
        pk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_sphincs_a_sm3_128s_simple_std_sign_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_sphincs_a_sm3_128s_simple_std_sign_signature(
        sm: *mut u8,
        sm_len: *mut usize,
        m: *const u8,
        m_len: usize,
        sk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_sphincs_a_sm3_128s_simple_std_sign_verify(
        sm: *const u8,
        sm_len: usize,
        m: *const u8,
        m_len: usize,
        pk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_sphincs_a_sm3_128s_simple_std_sign(
        sm: *mut u8,
        sm_len: *mut usize,
        m: *const u8,
        m_len: usize,
        sk: *const u8,
      ) -> c_int;
    }
    unsafe extern "C" {
      pub fn pqmagic_sphincs_a_sm3_128s_simple_std_sign_open(
        m: *mut u8,
        m_len: *mut usize,
        sm: *const u8,
        sm_len: usize,
        pk: *const u8,
      ) -> c_int;
    }
  }
}

#[cfg(test)]
mod tests {
  #[cfg(feature = "aigis_enc")]
  use super::kem::aigis_enc::*;
  #[cfg(feature = "kyber")]
  use super::kem::kyber::*;
  #[cfg(feature = "ml_kem")]
  use super::kem::ml_kem::*;
  use super::randombytes;
  #[cfg(feature = "aigis_sig")]
  use super::sig::aigis_sig::*;
  #[cfg(feature = "dilithium")]
  use super::sig::dilithium::*;
  #[cfg(feature = "ml_dsa")]
  use super::sig::ml_dsa::*;
  #[cfg(feature = "slh_dsa")]
  use super::sig::slh_dsa::*;
  #[cfg(feature = "sphincs_a")]
  use super::sig::sphincs_a::*;
  #[test]
  fn test_randombytes() {
    let mut out = [0u8; 32];
    let mut out2 = [0u8; 32];
    unsafe {
      randombytes(out.as_mut_ptr(), out.len());
      randombytes(out2.as_mut_ptr(), out2.len());
    }
    assert_ne!(out, out2);
  }

  #[test]
  #[cfg(feature = "kyber")]
  fn test_kyber512() {
    let mut pk = [0u8; KYBER512_PUBLICKEYBYTES as usize];
    let mut sk = [0u8; KYBER512_SECRETKEYBYTES as usize];
    let mut ct = [0u8; KYBER512_CIPHERTEXTBYTES as usize];
    let mut ss1 = [0u8; KYBER512_SSBYTES as usize];
    let mut ss2 = [0u8; KYBER512_SSBYTES as usize];

    unsafe {
      assert_eq!(pqmagic_kyber512_std_keypair(pk.as_mut_ptr(), sk.as_mut_ptr()), 0);
      assert_eq!(pqmagic_kyber512_std_enc(ct.as_mut_ptr(), ss1.as_mut_ptr(), pk.as_ptr()), 0);
      assert_eq!(pqmagic_kyber512_std_dec(ss2.as_mut_ptr(), ct.as_ptr(), sk.as_ptr()), 0);
    }

    assert_eq!(ss1, ss2);
  }

  #[test]
  #[cfg(feature = "kyber")]
  fn test_kyber768() {
    let mut pk = [0u8; KYBER768_PUBLICKEYBYTES as usize];
    let mut sk = [0u8; KYBER768_SECRETKEYBYTES as usize];
    let mut ct = [0u8; KYBER768_CIPHERTEXTBYTES as usize];
    let mut ss1 = [0u8; KYBER768_SSBYTES as usize];
    let mut ss2 = [0u8; KYBER768_SSBYTES as usize];

    unsafe {
      assert_eq!(pqmagic_kyber768_std_keypair(pk.as_mut_ptr(), sk.as_mut_ptr()), 0);
      assert_eq!(pqmagic_kyber768_std_enc(ct.as_mut_ptr(), ss1.as_mut_ptr(), pk.as_ptr()), 0);
      assert_eq!(pqmagic_kyber768_std_dec(ss2.as_mut_ptr(), ct.as_ptr(), sk.as_ptr()), 0);
    }

    assert_eq!(ss1, ss2);
  }

  #[test]
  #[cfg(feature = "kyber")]
  fn test_kyber1024() {
    let mut pk = [0u8; KYBER1024_PUBLICKEYBYTES as usize];
    let mut sk = [0u8; KYBER1024_SECRETKEYBYTES as usize];
    let mut ct = [0u8; KYBER1024_CIPHERTEXTBYTES as usize];
    let mut ss1 = [0u8; KYBER1024_SSBYTES as usize];
    let mut ss2 = [0u8; KYBER1024_SSBYTES as usize];

    unsafe {
      assert_eq!(pqmagic_kyber1024_std_keypair(pk.as_mut_ptr(), sk.as_mut_ptr()), 0);
      assert_eq!(pqmagic_kyber1024_std_enc(ct.as_mut_ptr(), ss1.as_mut_ptr(), pk.as_ptr()), 0);
      assert_eq!(pqmagic_kyber1024_std_dec(ss2.as_mut_ptr(), ct.as_ptr(), sk.as_ptr()), 0);
    }

    assert_eq!(ss1, ss2);
  }

  #[test]
  #[cfg(feature = "ml_kem")]
  fn test_ml_kem_512() {
    let mut pk = [0u8; ML_KEM_512_PUBLICKEYBYTES as usize];
    let mut sk = [0u8; ML_KEM_512_SECRETKEYBYTES as usize];
    let mut ct = [0u8; ML_KEM_512_CIPHERTEXTBYTES as usize];
    let mut ss1 = [0u8; ML_KEM_512_SSBYTES as usize];
    let mut ss2 = [0u8; ML_KEM_512_SSBYTES as usize];

    unsafe {
      assert_eq!(pqmagic_ml_kem_512_std_keypair(pk.as_mut_ptr(), sk.as_mut_ptr()), 0);
      assert_eq!(pqmagic_ml_kem_512_std_enc(ct.as_mut_ptr(), ss1.as_mut_ptr(), pk.as_ptr()), 0);
      assert_eq!(pqmagic_ml_kem_512_std_dec(ss2.as_mut_ptr(), ct.as_ptr(), sk.as_ptr()), 0);
    }

    assert_eq!(ss1, ss2);
  }

  #[test]
  #[cfg(feature = "ml_kem")]
  fn test_ml_kem_768() {
    let mut pk = [0u8; ML_KEM_768_PUBLICKEYBYTES as usize];
    let mut sk = [0u8; ML_KEM_768_SECRETKEYBYTES as usize];
    let mut ct = [0u8; ML_KEM_768_CIPHERTEXTBYTES as usize];
    let mut ss1 = [0u8; ML_KEM_768_SSBYTES as usize];
    let mut ss2 = [0u8; ML_KEM_768_SSBYTES as usize];

    unsafe {
      assert_eq!(pqmagic_ml_kem_768_std_keypair(pk.as_mut_ptr(), sk.as_mut_ptr()), 0);
      assert_eq!(pqmagic_ml_kem_768_std_enc(ct.as_mut_ptr(), ss1.as_mut_ptr(), pk.as_ptr()), 0);
      assert_eq!(pqmagic_ml_kem_768_std_dec(ss2.as_mut_ptr(), ct.as_ptr(), sk.as_ptr()), 0);
    }

    assert_eq!(ss1, ss2);
  }

  #[test]
  #[cfg(feature = "ml_kem")]
  fn test_ml_kem_1024() {
    let mut pk = [0u8; ML_KEM_1024_PUBLICKEYBYTES as usize];
    let mut sk = [0u8; ML_KEM_1024_SECRETKEYBYTES as usize];
    let mut ct = [0u8; ML_KEM_1024_CIPHERTEXTBYTES as usize];
    let mut ss1 = [0u8; ML_KEM_1024_SSBYTES as usize];
    let mut ss2 = [0u8; ML_KEM_1024_SSBYTES as usize];

    unsafe {
      assert_eq!(pqmagic_ml_kem_1024_std_keypair(pk.as_mut_ptr(), sk.as_mut_ptr()), 0);
      assert_eq!(pqmagic_ml_kem_1024_std_enc(ct.as_mut_ptr(), ss1.as_mut_ptr(), pk.as_ptr()), 0);
      assert_eq!(pqmagic_ml_kem_1024_std_dec(ss2.as_mut_ptr(), ct.as_ptr(), sk.as_ptr()), 0);
    }

    assert_eq!(ss1, ss2);
  }

  #[test]
  #[cfg(feature = "aigis_enc")]
  fn test_aigis_enc_1() {
    let mut pk = [0u8; AIGIS_ENC_1_PUBLICKEYBYTES as usize];
    let mut sk = [0u8; AIGIS_ENC_1_SECRETKEYBYTES as usize];
    let mut ct = [0u8; AIGIS_ENC_1_CIPHERTEXTBYTES as usize];
    let mut ss1 = [0u8; AIGIS_ENC_1_SSBYTES as usize];
    let mut ss2 = [0u8; AIGIS_ENC_1_SSBYTES as usize];

    unsafe {
      assert_eq!(pqmagic_aigis_enc_1_std_keypair(pk.as_mut_ptr(), sk.as_mut_ptr()), 0);
      assert_eq!(pqmagic_aigis_enc_1_std_enc(ct.as_mut_ptr(), ss1.as_mut_ptr(), pk.as_ptr()), 0);
      assert_eq!(pqmagic_aigis_enc_1_std_dec(ss2.as_mut_ptr(), ct.as_ptr(), sk.as_ptr()), 0);
    }

    assert_eq!(ss1, ss2);
  }

  #[test]
  #[cfg(feature = "aigis_enc")]
  fn test_aigis_enc_2() {
    let mut pk = [0u8; AIGIS_ENC_2_PUBLICKEYBYTES as usize];
    let mut sk = [0u8; AIGIS_ENC_2_SECRETKEYBYTES as usize];
    let mut ct = [0u8; AIGIS_ENC_2_CIPHERTEXTBYTES as usize];
    let mut ss1 = [0u8; AIGIS_ENC_2_SSBYTES as usize];
    let mut ss2 = [0u8; AIGIS_ENC_2_SSBYTES as usize];

    unsafe {
      assert_eq!(pqmagic_aigis_enc_2_std_keypair(pk.as_mut_ptr(), sk.as_mut_ptr()), 0);
      assert_eq!(pqmagic_aigis_enc_2_std_enc(ct.as_mut_ptr(), ss1.as_mut_ptr(), pk.as_ptr()), 0);
      assert_eq!(pqmagic_aigis_enc_2_std_dec(ss2.as_mut_ptr(), ct.as_ptr(), sk.as_ptr()), 0);
    }

    assert_eq!(ss1, ss2);
  }

  #[test]
  #[cfg(feature = "aigis_enc")]
  fn test_aigis_enc_3() {
    let mut pk = [0u8; AIGIS_ENC_3_PUBLICKEYBYTES as usize];
    let mut sk = [0u8; AIGIS_ENC_3_SECRETKEYBYTES as usize];
    let mut ct = [0u8; AIGIS_ENC_3_CIPHERTEXTBYTES as usize];
    let mut ss1 = [0u8; AIGIS_ENC_3_SSBYTES as usize];
    let mut ss2 = [0u8; AIGIS_ENC_3_SSBYTES as usize];

    unsafe {
      assert_eq!(pqmagic_aigis_enc_3_std_keypair(pk.as_mut_ptr(), sk.as_mut_ptr()), 0);
      assert_eq!(pqmagic_aigis_enc_3_std_enc(ct.as_mut_ptr(), ss1.as_mut_ptr(), pk.as_ptr()), 0);
      assert_eq!(pqmagic_aigis_enc_3_std_dec(ss2.as_mut_ptr(), ct.as_ptr(), sk.as_ptr()), 0);
    }

    assert_eq!(ss1, ss2);
  }

  #[test]
  #[cfg(feature = "aigis_enc")]
  fn test_aigis_enc_4() {
    let mut pk = [0u8; AIGIS_ENC_4_PUBLICKEYBYTES];
    let mut sk = [0u8; AIGIS_ENC_4_SECRETKEYBYTES];
    let mut ct = [0u8; AIGIS_ENC_4_CIPHERTEXTBYTES];
    let mut ss1 = [0u8; AIGIS_ENC_4_SSBYTES];
    let mut ss2 = [0u8; AIGIS_ENC_4_SSBYTES];

    unsafe {
      assert_eq!(pqmagic_aigis_enc_4_std_keypair(pk.as_mut_ptr(), sk.as_mut_ptr()), 0);
      assert_eq!(pqmagic_aigis_enc_4_std_enc(ct.as_mut_ptr(), ss1.as_mut_ptr(), pk.as_ptr()), 0);
      assert_eq!(pqmagic_aigis_enc_4_std_dec(ss2.as_mut_ptr(), ct.as_ptr(), sk.as_ptr()), 0);
    }

    assert_eq!(ss1, ss2);
  }

  #[test]
  #[cfg(feature = "aigis_sig")]
  fn test_aigis_sig_1() {
    let mut pk = [0u8; AIGIS_SIG1_PUBLICKEYBYTES as usize];
    let mut sk = [0u8; AIGIS_SIG1_SECRETKEYBYTES as usize];
    let message = b"test message";
    let mut sig = [0u8; AIGIS_SIG1_SIGBYTES as usize];
    let mut sig_len = 0usize;
    let ctx = b"context";

    unsafe {
      assert_eq!(pqmagic_aigis_sig1_std_keypair(pk.as_mut_ptr(), sk.as_mut_ptr()), 0);
      assert_eq!(
        pqmagic_aigis_sig1_std_signature(
          sig.as_mut_ptr(),
          &mut sig_len,
          message.as_ptr(),
          message.len(),
          ctx.as_ptr(),
          ctx.len(),
          sk.as_ptr()
        ),
        0
      );
      assert_eq!(
        pqmagic_aigis_sig1_std_verify(
          sig.as_ptr(),
          sig_len,
          message.as_ptr(),
          message.len(),
          ctx.as_ptr(),
          ctx.len(),
          pk.as_ptr()
        ),
        0
      );
    }
  }

  #[test]
  #[cfg(feature = "aigis_sig")]
  fn test_aigis_sig_2() {
    let mut pk = [0u8; AIGIS_SIG2_PUBLICKEYBYTES as usize];
    let mut sk = [0u8; AIGIS_SIG2_SECRETKEYBYTES as usize];
    let message = b"test message";
    let mut sig = [0u8; AIGIS_SIG2_SIGBYTES as usize];
    let mut sig_len = 0usize;
    let ctx = b"context";

    unsafe {
      assert_eq!(pqmagic_aigis_sig2_std_keypair(pk.as_mut_ptr(), sk.as_mut_ptr()), 0);
      assert_eq!(
        pqmagic_aigis_sig2_std_signature(
          sig.as_mut_ptr(),
          &mut sig_len,
          message.as_ptr(),
          message.len(),
          ctx.as_ptr(),
          ctx.len(),
          sk.as_ptr()
        ),
        0
      );
      assert_eq!(
        pqmagic_aigis_sig2_std_verify(
          sig.as_ptr(),
          sig_len,
          message.as_ptr(),
          message.len(),
          ctx.as_ptr(),
          ctx.len(),
          pk.as_ptr()
        ),
        0
      );
    }
  }

  #[test]
  #[cfg(feature = "aigis_sig")]
  fn test_aigis_sig_3() {
    let mut pk = [0u8; AIGIS_SIG3_PUBLICKEYBYTES as usize];
    let mut sk = [0u8; AIGIS_SIG3_SECRETKEYBYTES as usize];
    let message = b"test message";
    let mut sig = [0u8; AIGIS_SIG3_SIGBYTES as usize];
    let mut sig_len = 0usize;
    let ctx = b"context";

    unsafe {
      assert_eq!(pqmagic_aigis_sig3_std_keypair(pk.as_mut_ptr(), sk.as_mut_ptr()), 0);
      assert_eq!(
        pqmagic_aigis_sig3_std_signature(
          sig.as_mut_ptr(),
          &mut sig_len,
          message.as_ptr(),
          message.len(),
          ctx.as_ptr(),
          ctx.len(),
          sk.as_ptr()
        ),
        0
      );
      assert_eq!(
        pqmagic_aigis_sig3_std_verify(
          sig.as_ptr(),
          sig_len,
          message.as_ptr(),
          message.len(),
          ctx.as_ptr(),
          ctx.len(),
          pk.as_ptr()
        ),
        0
      );
    }
  }

  #[test]
  #[cfg(feature = "dilithium")]
  fn test_dilithium2() {
    let mut pk = [0u8; DILITHIUM2_PUBLICKEYBYTES as usize];
    let mut sk = [0u8; DILITHIUM2_SECRETKEYBYTES as usize];
    let message = b"test message";
    let mut sig = [0u8; DILITHIUM2_SIGBYTES as usize];
    let mut sig_len = 0usize;

    unsafe {
      assert_eq!(pqmagic_dilithium2_std_keypair(pk.as_mut_ptr(), sk.as_mut_ptr()), 0);
      assert_eq!(
        pqmagic_dilithium2_std_signature(
          sig.as_mut_ptr(),
          &mut sig_len,
          message.as_ptr(),
          message.len(),
          sk.as_ptr()
        ),
        0
      );
      assert_eq!(
        pqmagic_dilithium2_std_verify(
          sig.as_ptr(),
          sig_len,
          message.as_ptr(),
          message.len(),
          pk.as_ptr()
        ),
        0
      );
    }
  }

  #[test]
  #[cfg(feature = "dilithium")]
  fn test_dilithium3() {
    let mut pk = [0u8; DILITHIUM3_PUBLICKEYBYTES as usize];
    let mut sk = [0u8; DILITHIUM3_SECRETKEYBYTES as usize];
    let message = b"test message";
    let mut sig = [0u8; DILITHIUM3_SIGBYTES as usize];
    let mut sig_len = 0usize;

    unsafe {
      assert_eq!(pqmagic_dilithium3_std_keypair(pk.as_mut_ptr(), sk.as_mut_ptr()), 0);
      assert_eq!(
        pqmagic_dilithium3_std_signature(
          sig.as_mut_ptr(),
          &mut sig_len,
          message.as_ptr(),
          message.len(),
          sk.as_ptr()
        ),
        0
      );
      assert_eq!(
        pqmagic_dilithium3_std_verify(
          sig.as_ptr(),
          sig_len,
          message.as_ptr(),
          message.len(),
          pk.as_ptr()
        ),
        0
      );
    }
  }

  #[test]
  #[cfg(feature = "dilithium")]
  fn test_dilithium5() {
    let mut pk = [0u8; DILITHIUM5_PUBLICKEYBYTES as usize];
    let mut sk = [0u8; DILITHIUM5_SECRETKEYBYTES as usize];
    let message = b"test message";
    let mut sig = [0u8; DILITHIUM5_SIGBYTES as usize];
    let mut sig_len = 0usize;

    unsafe {
      assert_eq!(pqmagic_dilithium5_std_keypair(pk.as_mut_ptr(), sk.as_mut_ptr()), 0);
      assert_eq!(
        pqmagic_dilithium5_std_signature(
          sig.as_mut_ptr(),
          &mut sig_len,
          message.as_ptr(),
          message.len(),
          sk.as_ptr()
        ),
        0
      );
      assert_eq!(
        pqmagic_dilithium5_std_verify(
          sig.as_ptr(),
          sig_len,
          message.as_ptr(),
          message.len(),
          pk.as_ptr()
        ),
        0
      );
    }
  }

  #[test]
  #[cfg(feature = "ml_dsa")]
  fn test_ml_dsa_44() {
    let mut pk = [0u8; 10000];
    let mut sk = [0u8; 10000];
    let message = b"test";
    let mut sig = [0u8; 10000];
    let mut sig_len = 0usize;
    let ctx = b"context";

    unsafe {
      assert_eq!(pqmagic_ml_dsa_44_std_keypair(pk.as_mut_ptr(), sk.as_mut_ptr()), 0);
      assert_eq!(
        pqmagic_ml_dsa_44_std_signature(
          sig.as_mut_ptr(),
          &mut sig_len,
          message.as_ptr(),
          message.len(),
          ctx.as_ptr(),
          ctx.len(),
          sk.as_ptr()
        ),
        0
      );
      // assert_eq!(
      //   pqmagic_ml_dsa_44_std_verify(
      //     sig.as_ptr(),
      //     sig_len,
      //     message.as_ptr(),
      //     message.len(),
      //     ctx.as_ptr(),
      //     ctx.len(),
      //     pk.as_ptr()
      //   ),
      //   0
      // );
    }
  }

  #[test]
  #[cfg(feature = "ml_dsa")]
  fn test_ml_dsa_65() {
    let mut pk = [0u8; ML_DSA_65_PUBLICKEYBYTES as usize];
    let mut sk = [0u8; ML_DSA_65_SECRETKEYBYTES as usize];
    let message = b"test message";
    let mut sig = [0u8; ML_DSA_65_SIGBYTES as usize];
    let mut sig_len = 0usize;
    let ctx = b"context";

    unsafe {
      assert_eq!(pqmagic_ml_dsa_65_std_keypair(pk.as_mut_ptr(), sk.as_mut_ptr()), 0);
      assert_eq!(
        pqmagic_ml_dsa_65_std_signature(
          sig.as_mut_ptr(),
          &mut sig_len,
          message.as_ptr(),
          message.len(),
          ctx.as_ptr(),
          ctx.len(),
          sk.as_ptr()
        ),
        0
      );
      assert_eq!(
        pqmagic_ml_dsa_65_std_verify(
          sig.as_ptr(),
          sig_len,
          message.as_ptr(),
          message.len(),
          ctx.as_ptr(),
          ctx.len(),
          pk.as_ptr()
        ),
        0
      );
    }
  }

  #[test]
  #[cfg(feature = "ml_dsa")]
  fn test_ml_dsa_87() {
    let mut pk = [0u8; ML_DSA_87_PUBLICKEYBYTES as usize];
    let mut sk = [0u8; ML_DSA_87_SECRETKEYBYTES as usize];
    let message = b"test message";
    let mut sig = [0u8; ML_DSA_87_SIGBYTES as usize];
    let mut sig_len = 0usize;
    let ctx = b"context";

    unsafe {
      assert_eq!(pqmagic_ml_dsa_87_std_keypair(pk.as_mut_ptr(), sk.as_mut_ptr()), 0);
      assert_eq!(
        pqmagic_ml_dsa_87_std_signature(
          sig.as_mut_ptr(),
          &mut sig_len,
          message.as_ptr(),
          message.len(),
          ctx.as_ptr(),
          ctx.len(),
          sk.as_ptr()
        ),
        0
      );
      assert_eq!(
        pqmagic_ml_dsa_87_std_verify(
          sig.as_ptr(),
          sig_len,
          message.as_ptr(),
          message.len(),
          ctx.as_ptr(),
          ctx.len(),
          pk.as_ptr()
        ),
        0
      );
    }
  }

  #[test]
  #[cfg(feature = "sphincs_a")]
  fn test_sphincs_a_sha2_128f() {
    let mut pk = [0u8; SPHINCS_A_SHA2_128f_PUBLICKEYBYTES as usize];
    let mut sk = [0u8; SPHINCS_A_SHA2_128f_SECRETKEYBYTES as usize];
    let message = b"test message";
    let mut sig = [0u8; SPHINCS_A_SHA2_128f_SIGBYTES as usize];
    let mut sig_len = 0usize;

    unsafe {
      assert_eq!(
        pqmagic_sphincs_a_sha2_128f_simple_std_sign_keypair(pk.as_mut_ptr(), sk.as_mut_ptr()),
        0
      );
      assert_eq!(
        pqmagic_sphincs_a_sha2_128f_simple_std_sign_signature(
          sig.as_mut_ptr(),
          &mut sig_len,
          message.as_ptr(),
          message.len(),
          sk.as_ptr()
        ),
        0
      );
      assert_eq!(
        pqmagic_sphincs_a_sha2_128f_simple_std_sign_verify(
          sig.as_ptr(),
          sig_len,
          message.as_ptr(),
          message.len(),
          pk.as_ptr()
        ),
        0
      );
    }
  }

  #[test]
  #[cfg(feature = "sphincs_a")]
  fn test_sphincs_a_sha2_128s() {
    let mut pk = [0u8; SPHINCS_A_SHA2_128s_PUBLICKEYBYTES as usize];
    let mut sk = [0u8; SPHINCS_A_SHA2_128s_SECRETKEYBYTES as usize];
    let message = b"test message";
    let mut sig = [0u8; SPHINCS_A_SHA2_128s_SIGBYTES as usize];
    let mut sig_len = 0usize;

    unsafe {
      assert_eq!(
        pqmagic_sphincs_a_sha2_128s_simple_std_sign_keypair(pk.as_mut_ptr(), sk.as_mut_ptr()),
        0
      );
      assert_eq!(
        pqmagic_sphincs_a_sha2_128s_simple_std_sign_signature(
          sig.as_mut_ptr(),
          &mut sig_len,
          message.as_ptr(),
          message.len(),
          sk.as_ptr()
        ),
        0
      );
      assert_eq!(
        pqmagic_sphincs_a_sha2_128s_simple_std_sign_verify(
          sig.as_ptr(),
          sig_len,
          message.as_ptr(),
          message.len(),
          pk.as_ptr()
        ),
        0
      );
    }
  }

  #[test]
  #[cfg(feature = "sphincs_a")]
  fn test_sphincs_a_sha2_192f() {
    let mut pk = [0u8; SPHINCS_A_SHA2_192f_PUBLICKEYBYTES as usize];
    let mut sk = [0u8; SPHINCS_A_SHA2_192f_SECRETKEYBYTES as usize];
    let message = b"test message";
    let mut sig = [0u8; SPHINCS_A_SHA2_192f_SIGBYTES as usize];
    let mut sig_len = 0usize;

    unsafe {
      assert_eq!(
        pqmagic_sphincs_a_sha2_192f_simple_std_sign_keypair(pk.as_mut_ptr(), sk.as_mut_ptr()),
        0
      );
      assert_eq!(
        pqmagic_sphincs_a_sha2_192f_simple_std_sign_signature(
          sig.as_mut_ptr(),
          &mut sig_len,
          message.as_ptr(),
          message.len(),
          sk.as_ptr()
        ),
        0
      );
      assert_eq!(
        pqmagic_sphincs_a_sha2_192f_simple_std_sign_verify(
          sig.as_ptr(),
          sig_len,
          message.as_ptr(),
          message.len(),
          pk.as_ptr()
        ),
        0
      );
    }
  }

  #[test]
  #[cfg(feature = "sphincs_a")]
  fn test_sphincs_a_sha2_192s() {
    let mut pk = [0u8; SPHINCS_A_SHA2_192s_PUBLICKEYBYTES as usize];
    let mut sk = [0u8; SPHINCS_A_SHA2_192s_SECRETKEYBYTES as usize];
    let message = b"test message";
    let mut sig = [0u8; SPHINCS_A_SHA2_192s_SIGBYTES as usize];
    let mut sig_len = 0usize;

    unsafe {
      assert_eq!(
        pqmagic_sphincs_a_sha2_192s_simple_std_sign_keypair(pk.as_mut_ptr(), sk.as_mut_ptr()),
        0
      );
      assert_eq!(
        pqmagic_sphincs_a_sha2_192s_simple_std_sign_signature(
          sig.as_mut_ptr(),
          &mut sig_len,
          message.as_ptr(),
          message.len(),
          sk.as_ptr()
        ),
        0
      );
      assert_eq!(
        pqmagic_sphincs_a_sha2_192s_simple_std_sign_verify(
          sig.as_ptr(),
          sig_len,
          message.as_ptr(),
          message.len(),
          pk.as_ptr()
        ),
        0
      );
    }
  }

  #[test]
  #[cfg(feature = "sphincs_a")]
  fn test_sphincs_a_sha2_256f() {
    let mut pk = [0u8; SPHINCS_A_SHA2_256f_PUBLICKEYBYTES as usize];
    let mut sk = [0u8; SPHINCS_A_SHA2_256f_SECRETKEYBYTES as usize];
    let message = b"test message";
    let mut sig = [0u8; SPHINCS_A_SHA2_256f_SIGBYTES as usize];
    let mut sig_len = 0usize;

    unsafe {
      assert_eq!(
        pqmagic_sphincs_a_sha2_256f_simple_std_sign_keypair(pk.as_mut_ptr(), sk.as_mut_ptr()),
        0
      );
      assert_eq!(
        pqmagic_sphincs_a_sha2_256f_simple_std_sign_signature(
          sig.as_mut_ptr(),
          &mut sig_len,
          message.as_ptr(),
          message.len(),
          sk.as_ptr()
        ),
        0
      );
      assert_eq!(
        pqmagic_sphincs_a_sha2_256f_simple_std_sign_verify(
          sig.as_ptr(),
          sig_len,
          message.as_ptr(),
          message.len(),
          pk.as_ptr()
        ),
        0
      );
    }
  }

  #[test]
  #[cfg(feature = "sphincs_a")]
  fn test_sphincs_a_sha2_256s() {
    let mut pk = [0u8; SPHINCS_A_SHA2_256s_PUBLICKEYBYTES as usize];
    let mut sk = [0u8; SPHINCS_A_SHA2_256s_SECRETKEYBYTES as usize];
    let message = b"test message";
    let mut sig = [0u8; SPHINCS_A_SHA2_256s_SIGBYTES as usize];
    let mut sig_len = 0usize;

    unsafe {
      assert_eq!(
        pqmagic_sphincs_a_sha2_256s_simple_std_sign_keypair(pk.as_mut_ptr(), sk.as_mut_ptr()),
        0
      );
      assert_eq!(
        pqmagic_sphincs_a_sha2_256s_simple_std_sign_signature(
          sig.as_mut_ptr(),
          &mut sig_len,
          message.as_ptr(),
          message.len(),
          sk.as_ptr()
        ),
        0
      );
      assert_eq!(
        pqmagic_sphincs_a_sha2_256s_simple_std_sign_verify(
          sig.as_ptr(),
          sig_len,
          message.as_ptr(),
          message.len(),
          pk.as_ptr()
        ),
        0
      );
    }
  }

  #[test]
  #[cfg(all(feature = "sphincs_a", not(feature = "shake")))]
  fn test_sphincs_a_sm3_128f() {
    let mut pk = [0u8; SPHINCS_A_SM3_128f_PUBLICKEYBYTES as usize];
    let mut sk = [0u8; SPHINCS_A_SM3_128f_SECRETKEYBYTES as usize];
    let message = b"test message";
    let mut sig = [0u8; SPHINCS_A_SM3_128f_SIGBYTES as usize];
    let mut sig_len = 0usize;

    unsafe {
      assert_eq!(
        pqmagic_sphincs_a_sm3_128f_simple_std_sign_keypair(pk.as_mut_ptr(), sk.as_mut_ptr()),
        0
      );
      assert_eq!(
        pqmagic_sphincs_a_sm3_128f_simple_std_sign_signature(
          sig.as_mut_ptr(),
          &mut sig_len,
          message.as_ptr(),
          message.len(),
          sk.as_ptr()
        ),
        0
      );
      assert_eq!(
        pqmagic_sphincs_a_sm3_128f_simple_std_sign_verify(
          sig.as_ptr(),
          sig_len,
          message.as_ptr(),
          message.len(),
          pk.as_ptr()
        ),
        0
      );
    }
  }

  #[test]
  #[cfg(all(feature = "sphincs_a", not(feature = "shake")))]
  fn test_sphincs_a_sm3_128s() {
    let mut pk = [0u8; SPHINCS_A_SM3_128s_PUBLICKEYBYTES as usize];
    let mut sk = [0u8; SPHINCS_A_SM3_128s_SECRETKEYBYTES as usize];
    let message = b"test message";
    let mut sig = [0u8; SPHINCS_A_SM3_128s_SIGBYTES as usize];
    let mut sig_len = 0usize;

    unsafe {
      assert_eq!(
        pqmagic_sphincs_a_sm3_128s_simple_std_sign_keypair(pk.as_mut_ptr(), sk.as_mut_ptr()),
        0
      );
      assert_eq!(
        pqmagic_sphincs_a_sm3_128s_simple_std_sign_signature(
          sig.as_mut_ptr(),
          &mut sig_len,
          message.as_ptr(),
          message.len(),
          sk.as_ptr()
        ),
        0
      );
      assert_eq!(
        pqmagic_sphincs_a_sm3_128s_simple_std_sign_verify(
          sig.as_ptr(),
          sig_len,
          message.as_ptr(),
          message.len(),
          pk.as_ptr()
        ),
        0
      );
    }
  }
  #[test]
  #[cfg(all(feature = "sphincs_a", feature = "shake"))]
  fn test_sphincs_a_shake_128f() {
    let mut pk = [0u8; SPHINCS_A_SHAKE_128f_PUBLICKEYBYTES as usize];
    let mut sk = [0u8; SPHINCS_A_SHAKE_128f_SECRETKEYBYTES as usize];
    let message = b"test message";
    let mut sig = [0u8; SPHINCS_A_SHAKE_128f_SIGBYTES as usize];
    let mut sig_len = 0usize;

    unsafe {
      assert_eq!(
        pqmagic_sphincs_a_shake_128f_simple_std_sign_keypair(pk.as_mut_ptr(), sk.as_mut_ptr()),
        0
      );
      assert_eq!(
        pqmagic_sphincs_a_shake_128f_simple_std_sign_signature(
          sig.as_mut_ptr(),
          &mut sig_len,
          message.as_ptr(),
          message.len(),
          sk.as_ptr()
        ),
        0
      );
      assert_eq!(
        pqmagic_sphincs_a_shake_128f_simple_std_sign_verify(
          sig.as_ptr(),
          sig_len,
          message.as_ptr(),
          message.len(),
          pk.as_ptr()
        ),
        0
      );
    }
  }

  #[test]
  #[cfg(all(feature = "sphincs_a", feature = "shake"))]
  fn test_sphincs_a_shake_128s() {
    let mut pk = [0u8; SPHINCS_A_SHAKE_128s_PUBLICKEYBYTES as usize];
    let mut sk = [0u8; SPHINCS_A_SHAKE_128s_SECRETKEYBYTES as usize];
    let message = b"test message";
    let mut sig = [0u8; SPHINCS_A_SHAKE_128s_SIGBYTES as usize];
    let mut sig_len = 0usize;

    unsafe {
      assert_eq!(
        pqmagic_sphincs_a_shake_128s_simple_std_sign_keypair(pk.as_mut_ptr(), sk.as_mut_ptr()),
        0
      );
      assert_eq!(
        pqmagic_sphincs_a_shake_128s_simple_std_sign_signature(
          sig.as_mut_ptr(),
          &mut sig_len,
          message.as_ptr(),
          message.len(),
          sk.as_ptr()
        ),
        0
      );
      assert_eq!(
        pqmagic_sphincs_a_shake_128s_simple_std_sign_verify(
          sig.as_ptr(),
          sig_len,
          message.as_ptr(),
          message.len(),
          pk.as_ptr()
        ),
        0
      );
    }
  }

  #[test]
  #[cfg(all(feature = "sphincs_a", feature = "shake"))]
  fn test_sphincs_a_shake_192f() {
    let mut pk = [0u8; SPHINCS_A_SHAKE_192f_PUBLICKEYBYTES as usize];
    let mut sk = [0u8; SPHINCS_A_SHAKE_192f_SECRETKEYBYTES as usize];
    let message = b"test message";
    let mut sig = [0u8; SPHINCS_A_SHAKE_192f_SIGBYTES as usize];
    let mut sig_len = 0usize;

    unsafe {
      assert_eq!(
        pqmagic_sphincs_a_shake_192f_simple_std_sign_keypair(pk.as_mut_ptr(), sk.as_mut_ptr()),
        0
      );
      assert_eq!(
        pqmagic_sphincs_a_shake_192f_simple_std_sign_signature(
          sig.as_mut_ptr(),
          &mut sig_len,
          message.as_ptr(),
          message.len(),
          sk.as_ptr()
        ),
        0
      );
      assert_eq!(
        pqmagic_sphincs_a_shake_192f_simple_std_sign_verify(
          sig.as_ptr(),
          sig_len,
          message.as_ptr(),
          message.len(),
          pk.as_ptr()
        ),
        0
      );
    }
  }

  #[test]
  #[cfg(all(feature = "sphincs_a", feature = "shake"))]
  fn test_sphincs_a_shake_192s() {
    let mut pk = [0u8; SPHINCS_A_SHAKE_192s_PUBLICKEYBYTES as usize];
    let mut sk = [0u8; SPHINCS_A_SHAKE_192s_SECRETKEYBYTES as usize];
    let message = b"test message";
    let mut sig = [0u8; SPHINCS_A_SHAKE_192s_SIGBYTES as usize];
    let mut sig_len = 0usize;

    unsafe {
      assert_eq!(
        pqmagic_sphincs_a_shake_192s_simple_std_sign_keypair(pk.as_mut_ptr(), sk.as_mut_ptr()),
        0
      );
      assert_eq!(
        pqmagic_sphincs_a_shake_192s_simple_std_sign_signature(
          sig.as_mut_ptr(),
          &mut sig_len,
          message.as_ptr(),
          message.len(),
          sk.as_ptr()
        ),
        0
      );
      assert_eq!(
        pqmagic_sphincs_a_shake_192s_simple_std_sign_verify(
          sig.as_ptr(),
          sig_len,
          message.as_ptr(),
          message.len(),
          pk.as_ptr()
        ),
        0
      );
    }
  }

  #[test]
  #[cfg(all(feature = "sphincs_a", feature = "shake"))]
  fn test_sphincs_a_shake_256f() {
    let mut pk = [0u8; SPHINCS_A_SHAKE_256f_PUBLICKEYBYTES as usize];
    let mut sk = [0u8; SPHINCS_A_SHAKE_256f_SECRETKEYBYTES as usize];
    let message = b"test message";
    let mut sig = [0u8; SPHINCS_A_SHAKE_256f_SIGBYTES as usize];
    let mut sig_len = 0usize;

    unsafe {
      assert_eq!(
        pqmagic_sphincs_a_shake_256f_simple_std_sign_keypair(pk.as_mut_ptr(), sk.as_mut_ptr()),
        0
      );
      assert_eq!(
        pqmagic_sphincs_a_shake_256f_simple_std_sign_signature(
          sig.as_mut_ptr(),
          &mut sig_len,
          message.as_ptr(),
          message.len(),
          sk.as_ptr()
        ),
        0
      );
      assert_eq!(
        pqmagic_sphincs_a_shake_256f_simple_std_sign_verify(
          sig.as_ptr(),
          sig_len,
          message.as_ptr(),
          message.len(),
          pk.as_ptr()
        ),
        0
      );
    }
  }

  #[test]
  #[cfg(all(feature = "sphincs_a", feature = "shake"))]
  fn test_sphincs_a_shake_256s() {
    let mut pk = [0u8; SPHINCS_A_SHAKE_256s_PUBLICKEYBYTES as usize];
    let mut sk = [0u8; SPHINCS_A_SHAKE_256s_SECRETKEYBYTES as usize];
    let message = b"test message";
    let mut sig = [0u8; SPHINCS_A_SHAKE_256s_SIGBYTES as usize];
    let mut sig_len = 0usize;

    unsafe {
      assert_eq!(
        pqmagic_sphincs_a_shake_256s_simple_std_sign_keypair(pk.as_mut_ptr(), sk.as_mut_ptr()),
        0
      );
      assert_eq!(
        pqmagic_sphincs_a_shake_256s_simple_std_sign_signature(
          sig.as_mut_ptr(),
          &mut sig_len,
          message.as_ptr(),
          message.len(),
          sk.as_ptr()
        ),
        0
      );
      assert_eq!(
        pqmagic_sphincs_a_shake_256s_simple_std_sign_verify(
          sig.as_ptr(),
          sig_len,
          message.as_ptr(),
          message.len(),
          pk.as_ptr()
        ),
        0
      );
    }
  }
  #[test]
  #[cfg(feature = "slh_dsa")]
  fn test_slh_dsa_sha2_128f() {
    let mut pk = [0u8; SLH_DSA_SHA2_128f_PUBLICKEYBYTES as usize];
    let mut sk = [0u8; SLH_DSA_SHA2_128f_SECRETKEYBYTES as usize];
    let message = b"test message";
    let mut sig = [0u8; SLH_DSA_SHA2_128f_SIGBYTES as usize];
    let mut sig_len = 0usize;

    unsafe {
      assert_eq!(
        pqmagic_slh_dsa_sha2_128f_simple_std_sign_keypair(pk.as_mut_ptr(), sk.as_mut_ptr()),
        0
      );
      assert_eq!(
        pqmagic_slh_dsa_sha2_128f_simple_std_sign_signature(
          sig.as_mut_ptr(),
          &mut sig_len,
          message.as_ptr(),
          message.len(),
          sk.as_ptr()
        ),
        0
      );
      assert_eq!(
        pqmagic_slh_dsa_sha2_128f_simple_std_sign_verify(
          sig.as_ptr(),
          sig_len,
          message.as_ptr(),
          message.len(),
          pk.as_ptr()
        ),
        0
      );
    }
  }

  #[test]
  #[cfg(feature = "slh_dsa")]
  fn test_slh_dsa_sha2_128s() {
    let mut pk = [0u8; SLH_DSA_SHA2_128s_PUBLICKEYBYTES as usize];
    let mut sk = [0u8; SLH_DSA_SHA2_128s_SECRETKEYBYTES as usize];
    let message = b"test message";
    let mut sig = [0u8; SLH_DSA_SHA2_128s_SIGBYTES as usize];
    let mut sig_len = 0usize;

    unsafe {
      assert_eq!(
        pqmagic_slh_dsa_sha2_128s_simple_std_sign_keypair(pk.as_mut_ptr(), sk.as_mut_ptr()),
        0
      );
      assert_eq!(
        pqmagic_slh_dsa_sha2_128s_simple_std_sign_signature(
          sig.as_mut_ptr(),
          &mut sig_len,
          message.as_ptr(),
          message.len(),
          sk.as_ptr()
        ),
        0
      );
      assert_eq!(
        pqmagic_slh_dsa_sha2_128s_simple_std_sign_verify(
          sig.as_ptr(),
          sig_len,
          message.as_ptr(),
          message.len(),
          pk.as_ptr()
        ),
        0
      );
    }
  }

  #[test]
  #[cfg(feature = "slh_dsa")]
  fn test_slh_dsa_sha2_192f() {
    let mut pk = [0u8; SLH_DSA_SHA2_192f_PUBLICKEYBYTES as usize];
    let mut sk = [0u8; SLH_DSA_SHA2_192f_SECRETKEYBYTES as usize];
    let message = b"test message";
    let mut sig = [0u8; SLH_DSA_SHA2_192f_SIGBYTES as usize];
    let mut sig_len = 0usize;

    unsafe {
      assert_eq!(
        pqmagic_slh_dsa_sha2_192f_simple_std_sign_keypair(pk.as_mut_ptr(), sk.as_mut_ptr()),
        0
      );
      assert_eq!(
        pqmagic_slh_dsa_sha2_192f_simple_std_sign_signature(
          sig.as_mut_ptr(),
          &mut sig_len,
          message.as_ptr(),
          message.len(),
          sk.as_ptr()
        ),
        0
      );
      assert_eq!(
        pqmagic_slh_dsa_sha2_192f_simple_std_sign_verify(
          sig.as_ptr(),
          sig_len,
          message.as_ptr(),
          message.len(),
          pk.as_ptr()
        ),
        0
      );
    }
  }

  #[test]
  #[cfg(feature = "slh_dsa")]
  fn test_slh_dsa_sha2_192s() {
    let mut pk = [0u8; SLH_DSA_SHA2_192s_PUBLICKEYBYTES as usize];
    let mut sk = [0u8; SLH_DSA_SHA2_192s_SECRETKEYBYTES as usize];
    let message = b"test message";
    let mut sig = [0u8; SLH_DSA_SHA2_192s_SIGBYTES as usize];
    let mut sig_len = 0usize;

    unsafe {
      assert_eq!(
        pqmagic_slh_dsa_sha2_192s_simple_std_sign_keypair(pk.as_mut_ptr(), sk.as_mut_ptr()),
        0
      );
      assert_eq!(
        pqmagic_slh_dsa_sha2_192s_simple_std_sign_signature(
          sig.as_mut_ptr(),
          &mut sig_len,
          message.as_ptr(),
          message.len(),
          sk.as_ptr()
        ),
        0
      );
      assert_eq!(
        pqmagic_slh_dsa_sha2_192s_simple_std_sign_verify(
          sig.as_ptr(),
          sig_len,
          message.as_ptr(),
          message.len(),
          pk.as_ptr()
        ),
        0
      );
    }
  }

  #[test]
  #[cfg(feature = "slh_dsa")]
  fn test_slh_dsa_sha2_256f() {
    let mut pk = [0u8; SLH_DSA_SHA2_256f_PUBLICKEYBYTES as usize];
    let mut sk = [0u8; SLH_DSA_SHA2_256f_SECRETKEYBYTES as usize];
    let message = b"test message";
    let mut sig = [0u8; SLH_DSA_SHA2_256f_SIGBYTES as usize];
    let mut sig_len = 0usize;

    unsafe {
      assert_eq!(
        pqmagic_slh_dsa_sha2_256f_simple_std_sign_keypair(pk.as_mut_ptr(), sk.as_mut_ptr()),
        0
      );
      assert_eq!(
        pqmagic_slh_dsa_sha2_256f_simple_std_sign_signature(
          sig.as_mut_ptr(),
          &mut sig_len,
          message.as_ptr(),
          message.len(),
          sk.as_ptr()
        ),
        0
      );
      assert_eq!(
        pqmagic_slh_dsa_sha2_256f_simple_std_sign_verify(
          sig.as_ptr(),
          sig_len,
          message.as_ptr(),
          message.len(),
          pk.as_ptr()
        ),
        0
      );
    }
  }

  #[test]
  #[cfg(feature = "slh_dsa")]
  fn test_slh_dsa_sha2_256s() {
    let mut pk = [0u8; SLH_DSA_SHA2_256s_PUBLICKEYBYTES as usize];
    let mut sk = [0u8; SLH_DSA_SHA2_256s_SECRETKEYBYTES as usize];
    let message = b"test message";
    let mut sig = [0u8; SLH_DSA_SHA2_256s_SIGBYTES as usize];
    let mut sig_len = 0usize;

    unsafe {
      assert_eq!(
        pqmagic_slh_dsa_sha2_256s_simple_std_sign_keypair(pk.as_mut_ptr(), sk.as_mut_ptr()),
        0
      );
      assert_eq!(
        pqmagic_slh_dsa_sha2_256s_simple_std_sign_signature(
          sig.as_mut_ptr(),
          &mut sig_len,
          message.as_ptr(),
          message.len(),
          sk.as_ptr()
        ),
        0
      );
      assert_eq!(
        pqmagic_slh_dsa_sha2_256s_simple_std_sign_verify(
          sig.as_ptr(),
          sig_len,
          message.as_ptr(),
          message.len(),
          pk.as_ptr()
        ),
        0
      );
    }
  }
  #[test]
  #[cfg(all(feature = "slh_dsa", not(feature = "shake")))]
  fn test_slh_dsa_sm3_128f() {
    let mut pk = [0u8; SLH_DSA_SM3_128f_PUBLICKEYBYTES as usize];
    let mut sk = [0u8; SLH_DSA_SM3_128f_SECRETKEYBYTES as usize];
    let message = b"test message";
    let mut sig = [0u8; SLH_DSA_SM3_128f_SIGBYTES as usize];
    let mut sig_len = 0usize;

    unsafe {
      assert_eq!(
        pqmagic_slh_dsa_sm3_128f_simple_std_sign_keypair(pk.as_mut_ptr(), sk.as_mut_ptr()),
        0
      );
      assert_eq!(
        pqmagic_slh_dsa_sm3_128f_simple_std_sign_signature(
          sig.as_mut_ptr(),
          &mut sig_len,
          message.as_ptr(),
          message.len(),
          sk.as_ptr()
        ),
        0
      );
      assert_eq!(
        pqmagic_slh_dsa_sm3_128f_simple_std_sign_verify(
          sig.as_ptr(),
          sig_len,
          message.as_ptr(),
          message.len(),
          pk.as_ptr()
        ),
        0
      );
    }
  }

  #[test]
  #[cfg(all(feature = "slh_dsa", not(feature = "shake")))]
  fn test_slh_dsa_sm3_128s() {
    let mut pk = [0u8; SLH_DSA_SM3_128s_PUBLICKEYBYTES as usize];
    let mut sk = [0u8; SLH_DSA_SM3_128s_SECRETKEYBYTES as usize];
    let message = b"test message";
    let mut sig = [0u8; SLH_DSA_SM3_128s_SIGBYTES as usize];
    let mut sig_len = 0usize;

    unsafe {
      assert_eq!(
        pqmagic_slh_dsa_sm3_128s_simple_std_sign_keypair(pk.as_mut_ptr(), sk.as_mut_ptr()),
        0
      );
      assert_eq!(
        pqmagic_slh_dsa_sm3_128s_simple_std_sign_signature(
          sig.as_mut_ptr(),
          &mut sig_len,
          message.as_ptr(),
          message.len(),
          sk.as_ptr()
        ),
        0
      );
      assert_eq!(
        pqmagic_slh_dsa_sm3_128s_simple_std_sign_verify(
          sig.as_ptr(),
          sig_len,
          message.as_ptr(),
          message.len(),
          pk.as_ptr()
        ),
        0
      );
    }
  }
  #[test]
  #[cfg(all(feature = "slh_dsa", feature = "shake"))]
  fn test_slh_dsa_shake_128f() {
    let mut pk = [0u8; SLH_DSA_SHAKE_128f_PUBLICKEYBYTES as usize];
    let mut sk = [0u8; SLH_DSA_SHAKE_128f_SECRETKEYBYTES as usize];
    let message = b"test message";
    let mut sig = [0u8; SLH_DSA_SHAKE_128f_SIGBYTES as usize];
    let mut sig_len = 0usize;

    unsafe {
      assert_eq!(
        pqmagic_slh_dsa_shake_128f_simple_std_sign_keypair(pk.as_mut_ptr(), sk.as_mut_ptr()),
        0
      );
      assert_eq!(
        pqmagic_slh_dsa_shake_128f_simple_std_sign_signature(
          sig.as_mut_ptr(),
          &mut sig_len,
          message.as_ptr(),
          message.len(),
          sk.as_ptr()
        ),
        0
      );
      assert_eq!(
        pqmagic_slh_dsa_shake_128f_simple_std_sign_verify(
          sig.as_ptr(),
          sig_len,
          message.as_ptr(),
          message.len(),
          pk.as_ptr()
        ),
        0
      );
    }
  }

  #[test]
  #[cfg(all(feature = "slh_dsa", feature = "shake"))]
  fn test_slh_dsa_shake_128s() {
    let mut pk = [0u8; SLH_DSA_SHAKE_128s_PUBLICKEYBYTES as usize];
    let mut sk = [0u8; SLH_DSA_SHAKE_128s_SECRETKEYBYTES as usize];
    let message = b"test message";
    let mut sig = [0u8; SLH_DSA_SHAKE_128s_SIGBYTES as usize];
    let mut sig_len = 0usize;

    unsafe {
      assert_eq!(
        pqmagic_slh_dsa_shake_128s_simple_std_sign_keypair(pk.as_mut_ptr(), sk.as_mut_ptr()),
        0
      );
      assert_eq!(
        pqmagic_slh_dsa_shake_128s_simple_std_sign_signature(
          sig.as_mut_ptr(),
          &mut sig_len,
          message.as_ptr(),
          message.len(),
          sk.as_ptr()
        ),
        0
      );
      assert_eq!(
        pqmagic_slh_dsa_shake_128s_simple_std_sign_verify(
          sig.as_ptr(),
          sig_len,
          message.as_ptr(),
          message.len(),
          pk.as_ptr()
        ),
        0
      );
    }
  }

  #[test]
  #[cfg(all(feature = "slh_dsa", feature = "shake"))]
  fn test_slh_dsa_shake_192f() {
    let mut pk = [0u8; SLH_DSA_SHAKE_192f_PUBLICKEYBYTES as usize];
    let mut sk = [0u8; SLH_DSA_SHAKE_192f_SECRETKEYBYTES as usize];
    let message = b"test message";
    let mut sig = [0u8; SLH_DSA_SHAKE_192f_SIGBYTES as usize];
    let mut sig_len = 0usize;

    unsafe {
      assert_eq!(
        pqmagic_slh_dsa_shake_192f_simple_std_sign_keypair(pk.as_mut_ptr(), sk.as_mut_ptr()),
        0
      );
      assert_eq!(
        pqmagic_slh_dsa_shake_192f_simple_std_sign_signature(
          sig.as_mut_ptr(),
          &mut sig_len,
          message.as_ptr(),
          message.len(),
          sk.as_ptr()
        ),
        0
      );
      assert_eq!(
        pqmagic_slh_dsa_shake_192f_simple_std_sign_verify(
          sig.as_ptr(),
          sig_len,
          message.as_ptr(),
          message.len(),
          pk.as_ptr()
        ),
        0
      );
    }
  }

  #[test]
  #[cfg(all(feature = "slh_dsa", feature = "shake"))]
  fn test_slh_dsa_shake_192s() {
    let mut pk = [0u8; SLH_DSA_SHAKE_192s_PUBLICKEYBYTES as usize];
    let mut sk = [0u8; SLH_DSA_SHAKE_192s_SECRETKEYBYTES as usize];
    let message = b"test message";
    let mut sig = [0u8; SLH_DSA_SHAKE_192s_SIGBYTES as usize];
    let mut sig_len = 0usize;

    unsafe {
      assert_eq!(
        pqmagic_slh_dsa_shake_192s_simple_std_sign_keypair(pk.as_mut_ptr(), sk.as_mut_ptr()),
        0
      );
      assert_eq!(
        pqmagic_slh_dsa_shake_192s_simple_std_sign_signature(
          sig.as_mut_ptr(),
          &mut sig_len,
          message.as_ptr(),
          message.len(),
          sk.as_ptr()
        ),
        0
      );
      assert_eq!(
        pqmagic_slh_dsa_shake_192s_simple_std_sign_verify(
          sig.as_ptr(),
          sig_len,
          message.as_ptr(),
          message.len(),
          pk.as_ptr()
        ),
        0
      );
    }
  }

  #[test]
  #[cfg(all(feature = "slh_dsa", feature = "shake"))]
  fn test_slh_dsa_shake_256f() {
    let mut pk = [0u8; SLH_DSA_SHAKE_256f_PUBLICKEYBYTES as usize];
    let mut sk = [0u8; SLH_DSA_SHAKE_256f_SECRETKEYBYTES as usize];
    let message = b"test message";
    let mut sig = [0u8; SLH_DSA_SHAKE_256f_SIGBYTES as usize];
    let mut sig_len = 0usize;

    unsafe {
      assert_eq!(
        pqmagic_slh_dsa_shake_256f_simple_std_sign_keypair(pk.as_mut_ptr(), sk.as_mut_ptr()),
        0
      );
      assert_eq!(
        pqmagic_slh_dsa_shake_256f_simple_std_sign_signature(
          sig.as_mut_ptr(),
          &mut sig_len,
          message.as_ptr(),
          message.len(),
          sk.as_ptr()
        ),
        0
      );
      assert_eq!(
        pqmagic_slh_dsa_shake_256f_simple_std_sign_verify(
          sig.as_ptr(),
          sig_len,
          message.as_ptr(),
          message.len(),
          pk.as_ptr()
        ),
        0
      );
    }
  }

  #[test]
  #[cfg(all(feature = "slh_dsa", feature = "shake"))]
  fn test_slh_dsa_shake_256s() {
    let mut pk = [0u8; SLH_DSA_SHAKE_256s_PUBLICKEYBYTES as usize];
    let mut sk = [0u8; SLH_DSA_SHAKE_256s_SECRETKEYBYTES as usize];
    let message = b"test message";
    let mut sig = [0u8; SLH_DSA_SHAKE_256s_SIGBYTES as usize];
    let mut sig_len = 0usize;

    unsafe {
      assert_eq!(
        pqmagic_slh_dsa_shake_256s_simple_std_sign_keypair(pk.as_mut_ptr(), sk.as_mut_ptr()),
        0
      );
      assert_eq!(
        pqmagic_slh_dsa_shake_256s_simple_std_sign_signature(
          sig.as_mut_ptr(),
          &mut sig_len,
          message.as_ptr(),
          message.len(),
          sk.as_ptr()
        ),
        0
      );
      assert_eq!(
        pqmagic_slh_dsa_shake_256s_simple_std_sign_verify(
          sig.as_ptr(),
          sig_len,
          message.as_ptr(),
          message.len(),
          pk.as_ptr()
        ),
        0
      );
    }
  }
}
