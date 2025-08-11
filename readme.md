# ravencrypt

ravencrypt — modular C library implementing ChaCha20-Poly1305 AEAD, HKDF-SHA256,
Poly1305 and utilities. It's written to be auditable, well-documented, and
self-contained with tests and benchmarks.

## Quickstart

make
./test_raven
./bench_raven

## Notes
- This implementation focuses on clarity and test coverage. For high-stakes
  production use prefer audited libraries (libsodium, OpenSSL) or use this
  project as a learning base.
- Constant-time improvements and CPU-specific optimizations are included where
  reasonable (constant-time compare, zeroing secrets). For hardened builds,
  enable compiler-specific intrinsics / assembly where necessary.
