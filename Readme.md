# Solana NoStd HMAC-DRBG

[![CI](https://github.com/blueshift-gg/solana-hmac-drbg/actions/workflows/ci.yml/badge.svg)](https://github.com/blueshift-gg/solana-hmac-drbg/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/solana-hmac-drbg.svg)](https://crates.io/crates/solana-hmac-drbg)
[![docs.rs](https://docs.rs/solana-hmac-drbg/badge.svg)](https://docs.rs/solana-hmac-drbg)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://github.com/blueshift-gg/solana-hmac-drbg/blob/master/LICENSE)

A more efficient, `no_std` HMAC-SHA-256 DRBG (Deterministic Random Bit Generator) for the Solana SVM. Built on [`solana-hmac-sha256`](https://crates.io/crates/solana-hmac-sha256), so every internal HMAC routes through the `sol_sha256` syscall on-chain and falls through to the `sha2` crate off-chain — the same API works in host code (tests, off-chain tooling).

DRBG is the construction used by [RFC 6979](https://datatracker.ietf.org/doc/html/rfc6979) for deterministic nonce generation. DRBG alone is not the full RFC 6979 implementation — a valid nonce must also be clamped to the curve subgroup. For the full implementation see [`solana-rfc6979`](https://github.com/blueshift-gg/solana-rfc6979).

## Quick start

```toml
[dependencies]
solana-hmac-drbg = "0.2.0"
```

```rust
use solana_hmac_drbg::HmacDrbg;

let private_key: [u8; 32] = [/* ... */];
let message_hash: [u8; 32] = [/* ... */];

let mut nonce = [0u8; 32];
HmacDrbg::new(&private_key, &message_hash).fill_bytes(&mut nonce);
```

The library is `#![no_std]`-clean for SBPF; no allocator setup required.

## Static syscalls

If your target supports the Upstream BPF / sBPFv3 static-syscall ABI, enable the `static-syscalls` feature. It transparently forwards to [`solana-hmac-sha256/static-syscalls`](https://crates.io/crates/solana-hmac-sha256), so the SBPF program calls `sol_sha256` directly instead of going through an `extern "C"` PLT relocation.

```toml
[dependencies]
solana-hmac-drbg = { version = "0.2.0", features = ["static-syscalls"] }
```

## Benchmarks

To reproduce the on-chain compute unit cost, install `cargo build-sbf` (Solana CLI) and run:

```sh
cargo test --test sbpf --jobs 1
```

The benchmark compiles the function into its own SBPF program and runs it through [Mollusk](https://github.com/anza-xyz/mollusk) via [`svm-unit-test`](https://crates.io/crates/svm-unit-test).

## License

Licensed under the [MIT License](https://github.com/blueshift-gg/solana-hmac-drbg/blob/master/LICENSE). The license includes the standard "as-is" warranty disclaimer — use at your own risk.
