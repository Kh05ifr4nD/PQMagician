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
    pub const ALG_ARR_EN: [&str; alg_cnt!($($lit)*)] = [
      $(
        #[cfg(feature = $lit)]
        $lit,
      )*
    ];

    pub const ALG_ARR_DIS: [&str; alg_cnt_dis!($($lit)*)] = [
      $(
        #[cfg(not(feature = $lit))]
        concat!("ENABLE_", convert_ascii_case!(upper, $lit)),
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
  #[cfg(feature = "adv")]
  compile_error!(
    r#"Open Source Version Only Support PQMagic-std. Please disable `adv` or contact as for further high performance support."#
  );
  cfg.define("ENABLE_TEST", "No").define("ENABLE_BENCH", "No");
  #[cfg(feature = "shake")]
  cfg.define("USE_SHAKE", "Yes");
  for alg_define in ALG_ARR_DIS {
    cfg.define(alg_define, "No");
  }
  cfg.build_target("pqmagic_static_target").build().join("build")
}

fn main() {
  let build_dir = build_from_source();
  println!("cargo:rustc-link-search=native={}", build_dir.display());
  println!("cargo:rustc-link-search=native={}", build_dir.join("utils").display());
  println!("cargo:rustc-link-lib=static=randombytes");
  if cfg!(feature = "shake") {
    println!("cargo:rustc-link-search=native={}", build_dir.join("hash").join("keccak").display());
    println!("cargo:rustc-link-lib=static=fips202");
  } else {
    println!("cargo:rustc-link-search=native={}", build_dir.join("hash").join("sm3").display());
    println!("cargo:rustc-link-lib=static=sm3");
  }
  println!("cargo:rustc-link-lib=static=pqmagic_std");
}
