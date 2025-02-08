# PQMagician: Rust bindings for PQMagic

**PQMagician** consists of port crates that integrate the [PQMagic](https://github.com/pqcrypto-cn/PQMagic), a high-performance post-quantum cryptographic algorithm C library, into the ecosystem of Rust.

- `pqmagic-sys`: This crate can build vendored `PQMagic` library with customizable configurations and provide *unsafe* FFI bindings.
- `pqmagic`(todo): A high-level Rust wrapper crate based on `pqmagic-sys` for the safe access to cryptographic schemes in `PQMagic`.
