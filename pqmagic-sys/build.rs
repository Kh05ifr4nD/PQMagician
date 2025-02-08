macro_rules! alg_cnt {
  () => { 0 };
  ($head:literal $($tail:literal)*) => {
    if cfg!(feature = $head) {
      1 + alg_cnt!($($tail)*)
    } else {
      alg_cnt!($($tail)*)
    }
  };
}

macro_rules! alg_cnt_dis {
  () => { 0 };
  ($head:literal $($tail:literal)*) => {
    if cfg!(not(feature = $head)) {
      1 + alg_cnt_dis!($($tail)*)
    } else {
      alg_cnt_dis!($($tail)*)
    }
  };
}

macro_rules! feat_alg_gen {
  ($($lit:literal),*) => {
    pub const EN_ALG_ARR: [&str; alg_cnt!($($lit)*)] = [
      $(
        #[cfg(feature = $lit)]
        $lit,
      )*
    ];

    pub const DIS_ALG_CMAKE_ARR: [&str; alg_cnt_dis!($($lit)*)] = [
      $(
        #[cfg(not(feature = $lit))]
        const_str::concat!("ENABLE_", const_str::convert_ascii_case!(upper, $lit)),
      )*
    ];
  };
}

feat_alg_gen!(
  // KEM
  "aigis_enc",
  "kyber",
  "ml_kem",
  // SIG
  "aigis_sig",
  "dilithium",
  "ml_dsa",
  "slh_dsa",
  "sphincs_a"
);

fn build_from_source() -> std::path::PathBuf {
  let mut cfg = cmake::Config::new("PQMagic");
  cfg.define("ENABLE_TEST", "No").define("ENABLE_BENCH", "No");
  #[cfg(feature = "shake")]
  cfg.define("USE_SHAKE", "Yes");
  for alg_define in DIS_ALG_CMAKE_ARR {
    cfg.define(alg_define, "No");
  }
  cfg.build_target("pqmagic_static_target").build().join("build")
}

fn main() {
  #[cfg(all(
    not(feature = "aigis_enc"),
    not(feature = "kyber"),
    not(feature = "ml_kem"),
    not(feature = "aigis_sig"),
    not(feature = "dilithium"),
    not(feature = "ml_dsa"),
    not(feature = "slh_dsa"),
    not(feature = "sphincs_a")
  ))]
  compile_error!("Please enable at least one algorithm feature.");
  #[cfg(feature = "adv")]
  compile_error!(
    r#"Open Source Version Only Support PQMagic-std. Please disable `adv` or contact as for further high performance support."#
  );
  println!("cargo:rustc-link-search=native={}", build_from_source().display());
  println!("cargo:rustc-link-lib=static=pqmagic_std");
}
