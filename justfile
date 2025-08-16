default:
    @direnv allow
    @just --list

stup-sbmdl:
    git submodule update --init --recursive

bd:
    cargo build --workspace --all-targets

bd-all:
    cargo build --workspace --all-targets --features=shake,sm3

test:
    cargo test --workspace

lint:
    cargo clippy --workspace --all-targets --features=shake,sm3 --profile test -- -D warnings

fmt:
    cargo fmt --all

fmt-ck:
    cargo fmt --all --check

cln:
    cargo clean

updt:
    cargo update
    git submodule update --remote --recursive

doc:
    cargo doc --workspace --features=shake,sm3 --no-deps

doc-open:
    cargo doc --workspace --features=shake,sm3 --no-deps --open

pre-cmt: fmt lint test

ci: bd-all test lint fmt-ck

dev: bd test

hkr:
    @if command -v cargo-hakari >/dev/null 2>&1; then \
        cargo hakari generate --diff; \
        cargo hakari verify; \
    else \
        echo "Installing cargo-hakari..."; \
        cargo install cargo-hakari; \
        cargo hakari generate --diff; \
        cargo hakari verify; \
    fi

rls-pp: ci doc
