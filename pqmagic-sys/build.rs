use std::path::PathBuf;

fn find_in_path(exe: &str) -> bool {
  use std::process::{Command, Stdio};
  #[cfg(windows)]
  let mut cmd = Command::new("where");
  #[cfg(not(windows))]
  let mut cmd = Command::new("which");
  cmd.arg(exe).stdout(Stdio::null()).stderr(Stdio::null());
  cmd.status().map(|s| s.success()).unwrap_or(false)
}

struct BuildEnv {
  generator: Option<String>,
  c_compiler: Option<String>,
  cxx_compiler: Option<String>,
}

impl BuildEnv {
  fn read() -> Self {
    use std::env;
    let get = |k: &str| env::var(k).ok().filter(|s| !s.is_empty());

    let mut generator = get("PQMAGIC_SYS_GENERATOR").or_else(|| get("CMAKE_GENERATOR"));
    if generator.is_none() && find_in_path("ninja") {
      generator = Some("Ninja".to_string());
    }

    let mut c_compiler = get("PQMAGIC_SYS_CC").or_else(|| get("CC"));
    let mut cxx_compiler = get("PQMAGIC_SYS_CXX").or_else(|| get("CXX"));
    if env::var("CARGO_CFG_WINDOWS").is_ok() && c_compiler.is_none() && cxx_compiler.is_none() {
      if find_in_path("clang-cl") {
        c_compiler = Some("clang-cl".to_string());
        cxx_compiler = Some("clang-cl".to_string());
      } else {
        println!(
          "cargo:warning=`clang-cl` not found in PATH; CMake may fall back to cl.exe, which is more likely to fail."
        );
      }
    }

    Self { generator, c_compiler, cxx_compiler }
  }
}

fn apply_algorithm_features(cfg: &mut cmake::Config) {
  macro_rules! set_alg {
    ($name:literal, $feat:literal) => {
      cfg.define(&format!("ENABLE_{}", $name), if cfg!(feature = $feat) { "ON" } else { "OFF" });
    };
  }

  // KEM
  set_alg!("AIGIS_ENC", "aigis_enc");
  set_alg!("KYBER", "kyber");
  set_alg!("ML_KEM", "ml_kem");
  // SIG
  set_alg!("AIGIS_SIG", "aigis_sig");
  set_alg!("DILITHIUM", "dilithium");
  set_alg!("ML_DSA", "ml_dsa");
  set_alg!("SLH_DSA", "slh_dsa");
  set_alg!("SPHINCS_A", "sphincs_a");

  if cfg!(feature = "shake") {
    cfg.define("USE_SHAKE", "ON");
  }
}

fn apply_env_to_cmake(cfg: &mut cmake::Config, envs: &BuildEnv) {
  cfg.profile("Release").define("ENABLE_TEST", "OFF").define("ENABLE_BENCH", "OFF");
  #[cfg(windows)]
  cfg.define("CMAKE_SYSTEM_VERSION", "10.0");
  apply_algorithm_features(cfg);
  if let Some(ref g) = envs.generator {
    cfg.generator(g);
  }
  if let Some(ref cc) = envs.c_compiler {
    cfg.define("CMAKE_C_COMPILER", cc);
  }
  if let Some(ref cxx) = envs.cxx_compiler {
    cfg.define("CMAKE_CXX_COMPILER", cxx);
  }
}

fn build_from_source() -> PathBuf {
  use std::env;

  let envs = BuildEnv::read();

  let mut cfg = cmake::Config::new("PQMagic");
  apply_env_to_cmake(&mut cfg, &envs);

  // (MSVC warnings are printed earlier during generator selection to surface guidance sooner.)

  for k in
    ["CMAKE_GENERATOR", "PQMAGIC_SYS_GENERATOR", "CC", "CXX", "PQMAGIC_SYS_CC", "PQMAGIC_SYS_CXX"]
  {
    println!("cargo:rerun-if-env-changed={k}");
  }

  let outdir = cfg.build();

  println!("cargo:rerun-if-changed=PQMagic/CMakeLists.txt");

  let libdir = outdir.join("lib");
  println!("cargo:rustc-link-search=native={}", libdir.display());

  if env::var("CARGO_CFG_WINDOWS").is_ok() {
    println!("cargo:rustc-link-lib=advapi32");
  }

  let link_name = if env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("gnu") {
    "pqmagic_std"
  } else {
    "libpqmagic_std"
  };
  println!("cargo:rustc-link-lib=static={link_name}");

  outdir
}

fn main() {
  // Guard against unsupported advanced variant
  #[cfg(feature = "adv")]
  compile_error!(
    "Open source version only supports PQMagic-std. Disable `adv` or contact the author for high-performance support."
  );

  // Require at least one algorithm feature
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

  let _ = build_from_source();
}
