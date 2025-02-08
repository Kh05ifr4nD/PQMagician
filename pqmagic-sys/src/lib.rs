#![no_std]
pub mod util {
  extern "C" {
    pub fn randombytes(out: *mut u8, out_len: usize);
  }
}

#[cfg(any(feature = "aigis_enc", feature = "ml_kem", feature = "kyber"))]
pub mod kem {
  #[cfg(feature = "aigis_enc")]
  pub mod aigis_enc;
  #[cfg(feature = "kyber")]
  pub mod kyber;
  #[cfg(feature = "ml_kem")]
  pub mod ml_kem;
}

#[cfg(any(
  feature = "aigis_sig",
  feature = "dilithium",
  feature = "ml_dsa",
  feature = "slh_dsa",
  feature = "sphincs_a"
))]
pub mod sig {
  #[cfg(feature = "aigis_sig")]
  pub mod aigis_sig;
  #[cfg(feature = "dilithium")]
  pub mod dilithium;
  #[cfg(feature = "ml_dsa")]
  pub mod ml_dsa;
  #[allow(non_upper_case_globals)]
  #[cfg(feature = "slh_dsa")]
  pub mod slh_dsa;
  #[allow(non_upper_case_globals)]
  #[cfg(feature = "sphincs_a")]
  pub mod sphincs_a;
}

#[allow(clippy::large_stack_arrays)]
#[cfg(test)]
mod tests {
  #[cfg(feature = "aigis_enc")]
  use super::kem::aigis_enc::*;
  #[cfg(feature = "kyber")]
  use super::kem::kyber::*;
  #[cfg(feature = "ml_kem")]
  use super::kem::ml_kem::*;
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
  use super::util::randombytes;

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
    let mut pk = [0u8; KYBER512_PUBLICKEYBYTES];
    let mut sk = [0u8; KYBER512_SECRETKEYBYTES];
    let mut ct = [0u8; KYBER512_CIPHERTEXTBYTES];
    let mut ss1 = [0u8; KYBER512_SSBYTES];
    let mut ss2 = [0u8; KYBER512_SSBYTES];

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
    let mut pk = [0u8; KYBER768_PUBLICKEYBYTES];
    let mut sk = [0u8; KYBER768_SECRETKEYBYTES];
    let mut ct = [0u8; KYBER768_CIPHERTEXTBYTES];
    let mut ss1 = [0u8; KYBER768_SSBYTES];
    let mut ss2 = [0u8; KYBER768_SSBYTES];

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
    let mut pk = [0u8; KYBER1024_PUBLICKEYBYTES];
    let mut sk = [0u8; KYBER1024_SECRETKEYBYTES];
    let mut ct = [0u8; KYBER1024_CIPHERTEXTBYTES];
    let mut ss1 = [0u8; KYBER1024_SSBYTES];
    let mut ss2 = [0u8; KYBER1024_SSBYTES];

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
    let mut pk = [0u8; ML_KEM_512_PUBLICKEYBYTES];
    let mut sk = [0u8; ML_KEM_512_SECRETKEYBYTES];
    let mut ct = [0u8; ML_KEM_512_CIPHERTEXTBYTES];
    let mut ss1 = [0u8; ML_KEM_512_SSBYTES];
    let mut ss2 = [0u8; ML_KEM_512_SSBYTES];

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
    let mut pk = [0u8; ML_KEM_768_PUBLICKEYBYTES];
    let mut sk = [0u8; ML_KEM_768_SECRETKEYBYTES];
    let mut ct = [0u8; ML_KEM_768_CIPHERTEXTBYTES];
    let mut ss1 = [0u8; ML_KEM_768_SSBYTES];
    let mut ss2 = [0u8; ML_KEM_768_SSBYTES];

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
    let mut pk = [0u8; ML_KEM_1024_PUBLICKEYBYTES];
    let mut sk = [0u8; ML_KEM_1024_SECRETKEYBYTES];
    let mut ct = [0u8; ML_KEM_1024_CIPHERTEXTBYTES];
    let mut ss1 = [0u8; ML_KEM_1024_SSBYTES];
    let mut ss2 = [0u8; ML_KEM_1024_SSBYTES];

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
    let mut pk = [0u8; AIGIS_ENC_1_PUBLICKEYBYTES];
    let mut sk = [0u8; AIGIS_ENC_1_SECRETKEYBYTES];
    let mut ct = [0u8; AIGIS_ENC_1_CIPHERTEXTBYTES];
    let mut ss1 = [0u8; AIGIS_ENC_1_SSBYTES];
    let mut ss2 = [0u8; AIGIS_ENC_1_SSBYTES];

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
    let mut pk = [0u8; AIGIS_ENC_2_PUBLICKEYBYTES];
    let mut sk = [0u8; AIGIS_ENC_2_SECRETKEYBYTES];
    let mut ct = [0u8; AIGIS_ENC_2_CIPHERTEXTBYTES];
    let mut ss1 = [0u8; AIGIS_ENC_2_SSBYTES];
    let mut ss2 = [0u8; AIGIS_ENC_2_SSBYTES];

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
    let mut pk = [0u8; AIGIS_ENC_3_PUBLICKEYBYTES];
    let mut sk = [0u8; AIGIS_ENC_3_SECRETKEYBYTES];
    let mut ct = [0u8; AIGIS_ENC_3_CIPHERTEXTBYTES];
    let mut ss1 = [0u8; AIGIS_ENC_3_SSBYTES];
    let mut ss2 = [0u8; AIGIS_ENC_3_SSBYTES];

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
    let mut pk = [0u8; AIGIS_SIG1_PUBLICKEYBYTES];
    let mut sk = [0u8; AIGIS_SIG1_SECRETKEYBYTES];
    let message = b"test message";
    let mut sig = [0u8; AIGIS_SIG1_SIGBYTES];
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
    let mut pk = [0u8; AIGIS_SIG2_PUBLICKEYBYTES];
    let mut sk = [0u8; AIGIS_SIG2_SECRETKEYBYTES];
    let message = b"test message";
    let mut sig = [0u8; AIGIS_SIG2_SIGBYTES];
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
    let mut pk = [0u8; AIGIS_SIG3_PUBLICKEYBYTES];
    let mut sk = [0u8; AIGIS_SIG3_SECRETKEYBYTES];
    let message = b"test message";
    let mut sig = [0u8; AIGIS_SIG3_SIGBYTES];
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
    let mut pk = [0u8; DILITHIUM2_PUBLICKEYBYTES];
    let mut sk = [0u8; DILITHIUM2_SECRETKEYBYTES];
    let message = b"test message";
    let mut sig = [0u8; DILITHIUM2_SIGBYTES];
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
    let mut pk = [0u8; DILITHIUM3_PUBLICKEYBYTES];
    let mut sk = [0u8; DILITHIUM3_SECRETKEYBYTES];
    let message = b"test message";
    let mut sig = [0u8; DILITHIUM3_SIGBYTES];
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
    let mut pk = [0u8; DILITHIUM5_PUBLICKEYBYTES];
    let mut sk = [0u8; DILITHIUM5_SECRETKEYBYTES];
    let message = b"test message";
    let mut sig = [0u8; DILITHIUM5_SIGBYTES];
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
    let mut pk = [0u8; ML_DSA_65_PUBLICKEYBYTES];
    let mut sk = [0u8; ML_DSA_65_SECRETKEYBYTES];
    let message = b"test message";
    let mut sig = [0u8; ML_DSA_65_SIGBYTES];
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
    let mut pk = [0u8; ML_DSA_87_PUBLICKEYBYTES];
    let mut sk = [0u8; ML_DSA_87_SECRETKEYBYTES];
    let message = b"test message";
    let mut sig = [0u8; ML_DSA_87_SIGBYTES];
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
    let mut pk = [0u8; SPHINCS_A_SHA2_128f_PUBLICKEYBYTES];
    let mut sk = [0u8; SPHINCS_A_SHA2_128f_SECRETKEYBYTES];
    let message = b"test message";
    let mut sig = [0u8; SPHINCS_A_SHA2_128f_SIGBYTES];
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
    let mut pk = [0u8; SPHINCS_A_SHA2_128s_PUBLICKEYBYTES];
    let mut sk = [0u8; SPHINCS_A_SHA2_128s_SECRETKEYBYTES];
    let message = b"test message";
    let mut sig = [0u8; SPHINCS_A_SHA2_128s_SIGBYTES];
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
    let mut pk = [0u8; SPHINCS_A_SHA2_192f_PUBLICKEYBYTES];
    let mut sk = [0u8; SPHINCS_A_SHA2_192f_SECRETKEYBYTES];
    let message = b"test message";
    let mut sig = [0u8; SPHINCS_A_SHA2_192f_SIGBYTES];
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
    let mut pk = [0u8; SPHINCS_A_SHA2_192s_PUBLICKEYBYTES];
    let mut sk = [0u8; SPHINCS_A_SHA2_192s_SECRETKEYBYTES];
    let message = b"test message";
    let mut sig = [0u8; SPHINCS_A_SHA2_192s_SIGBYTES];
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
    let mut pk = [0u8; SPHINCS_A_SHA2_256f_PUBLICKEYBYTES];
    let mut sk = [0u8; SPHINCS_A_SHA2_256f_SECRETKEYBYTES];
    let message = b"test message";
    let mut sig = [0u8; SPHINCS_A_SHA2_256f_SIGBYTES];
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
    let mut pk = [0u8; SPHINCS_A_SHA2_256s_PUBLICKEYBYTES];
    let mut sk = [0u8; SPHINCS_A_SHA2_256s_SECRETKEYBYTES];
    let message = b"test message";
    let mut sig = [0u8; SPHINCS_A_SHA2_256s_SIGBYTES];
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
  #[cfg(all(feature = "sphincs_a", feature = "sm3"))]
  fn test_sphincs_a_sm3_128f() {
    let mut pk = [0u8; SPHINCS_A_SM3_128f_PUBLICKEYBYTES];
    let mut sk = [0u8; SPHINCS_A_SM3_128f_SECRETKEYBYTES];
    let message = b"test message";
    let mut sig = [0u8; SPHINCS_A_SM3_128f_SIGBYTES];
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
  #[cfg(all(feature = "sphincs_a", feature = "sm3"))]
  fn test_sphincs_a_sm3_128s() {
    let mut pk = [0u8; SPHINCS_A_SM3_128s_PUBLICKEYBYTES];
    let mut sk = [0u8; SPHINCS_A_SM3_128s_SECRETKEYBYTES];
    let message = b"test message";
    let mut sig = [0u8; SPHINCS_A_SM3_128s_SIGBYTES];
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
    let mut pk = [0u8; SPHINCS_A_SHAKE_128f_PUBLICKEYBYTES];
    let mut sk = [0u8; SPHINCS_A_SHAKE_128f_SECRETKEYBYTES];
    let message = b"test message";
    let mut sig = [0u8; SPHINCS_A_SHAKE_128f_SIGBYTES];
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
    let mut pk = [0u8; SPHINCS_A_SHAKE_128s_PUBLICKEYBYTES];
    let mut sk = [0u8; SPHINCS_A_SHAKE_128s_SECRETKEYBYTES];
    let message = b"test message";
    let mut sig = [0u8; SPHINCS_A_SHAKE_128s_SIGBYTES];
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
    let mut pk = [0u8; SPHINCS_A_SHAKE_192f_PUBLICKEYBYTES];
    let mut sk = [0u8; SPHINCS_A_SHAKE_192f_SECRETKEYBYTES];
    let message = b"test message";
    let mut sig = [0u8; SPHINCS_A_SHAKE_192f_SIGBYTES];
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
    let mut pk = [0u8; SPHINCS_A_SHAKE_192s_PUBLICKEYBYTES];
    let mut sk = [0u8; SPHINCS_A_SHAKE_192s_SECRETKEYBYTES];
    let message = b"test message";
    let mut sig = [0u8; SPHINCS_A_SHAKE_192s_SIGBYTES];
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
    let mut pk = [0u8; SPHINCS_A_SHAKE_256f_PUBLICKEYBYTES];
    let mut sk = [0u8; SPHINCS_A_SHAKE_256f_SECRETKEYBYTES];
    let message = b"test message";
    let mut sig = [0u8; SPHINCS_A_SHAKE_256f_SIGBYTES];
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
    let mut pk = [0u8; SPHINCS_A_SHAKE_256s_PUBLICKEYBYTES];
    let mut sk = [0u8; SPHINCS_A_SHAKE_256s_SECRETKEYBYTES];
    let message = b"test message";
    let mut sig = [0u8; SPHINCS_A_SHAKE_256s_SIGBYTES];
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
    let mut pk = [0u8; SLH_DSA_SHA2_128f_PUBLICKEYBYTES];
    let mut sk = [0u8; SLH_DSA_SHA2_128f_SECRETKEYBYTES];
    let message = b"test message";
    let mut sig = [0u8; SLH_DSA_SHA2_128f_SIGBYTES];
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
    let mut pk = [0u8; SLH_DSA_SHA2_128s_PUBLICKEYBYTES];
    let mut sk = [0u8; SLH_DSA_SHA2_128s_SECRETKEYBYTES];
    let message = b"test message";
    let mut sig = [0u8; SLH_DSA_SHA2_128s_SIGBYTES];
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
    let mut pk = [0u8; SLH_DSA_SHA2_192f_PUBLICKEYBYTES];
    let mut sk = [0u8; SLH_DSA_SHA2_192f_SECRETKEYBYTES];
    let message = b"test message";
    let mut sig = [0u8; SLH_DSA_SHA2_192f_SIGBYTES];
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
    let mut pk = [0u8; SLH_DSA_SHA2_192s_PUBLICKEYBYTES];
    let mut sk = [0u8; SLH_DSA_SHA2_192s_SECRETKEYBYTES];
    let message = b"test message";
    let mut sig = [0u8; SLH_DSA_SHA2_192s_SIGBYTES];
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
    let mut pk = [0u8; SLH_DSA_SHA2_256f_PUBLICKEYBYTES];
    let mut sk = [0u8; SLH_DSA_SHA2_256f_SECRETKEYBYTES];
    let message = b"test message";
    let mut sig = [0u8; SLH_DSA_SHA2_256f_SIGBYTES];
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
    let mut pk = [0u8; SLH_DSA_SHA2_256s_PUBLICKEYBYTES];
    let mut sk = [0u8; SLH_DSA_SHA2_256s_SECRETKEYBYTES];
    let message = b"test message";
    let mut sig = [0u8; SLH_DSA_SHA2_256s_SIGBYTES];
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
  #[cfg(all(feature = "slh_dsa", feature = "sm3"))]
  fn test_slh_dsa_sm3_128f() {
    let mut pk = [0u8; SLH_DSA_SM3_128f_PUBLICKEYBYTES];
    let mut sk = [0u8; SLH_DSA_SM3_128f_SECRETKEYBYTES];
    let message = b"test message";
    let mut sig = [0u8; SLH_DSA_SM3_128f_SIGBYTES];
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
  #[cfg(all(feature = "slh_dsa", feature = "sm3"))]
  fn test_slh_dsa_sm3_128s() {
    let mut pk = [0u8; SLH_DSA_SM3_128s_PUBLICKEYBYTES];
    let mut sk = [0u8; SLH_DSA_SM3_128s_SECRETKEYBYTES];
    let message = b"test message";
    let mut sig = [0u8; SLH_DSA_SM3_128s_SIGBYTES];
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
    let mut pk = [0u8; SLH_DSA_SHAKE_128f_PUBLICKEYBYTES];
    let mut sk = [0u8; SLH_DSA_SHAKE_128f_SECRETKEYBYTES];
    let message = b"test message";
    let mut sig = [0u8; SLH_DSA_SHAKE_128f_SIGBYTES];
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
    let mut pk = [0u8; SLH_DSA_SHAKE_128s_PUBLICKEYBYTES];
    let mut sk = [0u8; SLH_DSA_SHAKE_128s_SECRETKEYBYTES];
    let message = b"test message";
    let mut sig = [0u8; SLH_DSA_SHAKE_128s_SIGBYTES];
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
    let mut pk = [0u8; SLH_DSA_SHAKE_192f_PUBLICKEYBYTES];
    let mut sk = [0u8; SLH_DSA_SHAKE_192f_SECRETKEYBYTES];
    let message = b"test message";
    let mut sig = [0u8; SLH_DSA_SHAKE_192f_SIGBYTES];
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
    let mut pk = [0u8; SLH_DSA_SHAKE_192s_PUBLICKEYBYTES];
    let mut sk = [0u8; SLH_DSA_SHAKE_192s_SECRETKEYBYTES];
    let message = b"test message";
    let mut sig = [0u8; SLH_DSA_SHAKE_192s_SIGBYTES];
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
    let mut pk = [0u8; SLH_DSA_SHAKE_256f_PUBLICKEYBYTES];
    let mut sk = [0u8; SLH_DSA_SHAKE_256f_SECRETKEYBYTES];
    let message = b"test message";
    let mut sig = [0u8; SLH_DSA_SHAKE_256f_SIGBYTES];
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
    let mut pk = [0u8; SLH_DSA_SHAKE_256s_PUBLICKEYBYTES];
    let mut sk = [0u8; SLH_DSA_SHAKE_256s_SECRETKEYBYTES];
    let message = b"test message";
    let mut sig = [0u8; SLH_DSA_SHAKE_256s_SIGBYTES];
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
