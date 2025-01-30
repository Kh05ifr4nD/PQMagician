# PQMagician: Rust bindings for PQMagic

**PQMagician** consists of port crates that integrate the [PQMagic](https://github.com/pqcrypto-cn/PQMagic), a high-performance post-quantum cryptographic algorithm C library, into the Rust ecosystem.

- `pqmagic-sys`: This crate builds vendored `PQMagic` library with customizable configurations and provides *unsafe* FFI bindings to it.
- `pqmagic`(todo): A high-level Rust wrapper crate based on `pqmagic-sys` for the safe access to cryptographic schemes in `PQMagic`.
