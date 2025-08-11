# ravencrypt

Now includes:
 - ChaCha20-Poly1305 AEAD (native)
 - AES-GCM (OpenSSL wrapper; compile with `make OPENSSL=1`)
 - BLAKE2s (pure C)

Build instructions:
 - Linux (with OpenSSL): `make OPENSSL=1`
 - Without OpenSSL: `make`

Run tests: `./test_raven`
Run benchmark: `./bench_raven`

Security / portability notes: AES-GCM requires linking OpenSSL; BLAKE2s is internal and portable.