//! # pqmagic-sys
//!
//! This sys-crate offers low-level *unsafe* FFI bindings to vendored or native [PQMagic](https://github.com/pqcrypto-cn/PQMagic) C library, and accessible kem/sig schemes and modes are controlled by specified features.

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
