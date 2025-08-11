# Ravencrypt

**A powerful, modular, and original hybrid encryption library**

---

## Table of Contents

* [Overview](#overview)
* [Features](#features)
* [Installation](#installation)
* [Usage](#usage)
* [API Functions](#api-functions)
* [Benchmark](#benchmark)
* [Contributing](#contributing)
* [License](#license)

---

## Overview

Ravencrypt is a high-performance hybrid encryption library developed with modern cryptographic standards and original algorithms.
It combines proven algorithms like AES-GCM and ChaCha20-Poly1305 with Argon2-based KDF, HKDF, and a hybrid encryption architecture to provide enhanced security.

---

## Features

* Symmetric encryption using **AES-GCM** and **ChaCha20-Poly1305**
* Hybrid encryption structure for increased security and flexibility
* Strong key derivation using **Argon2id KDF**
* **HKDF** key derivation function support
* Secure nonce and MAC management
* Performance benchmarks and testing tools
* Clean and extensible API for easy integration
* Built upon `libsodium` and `OpenSSL` libraries

---

## Installation

### Requirements

* GCC (supporting C11)
* OpenSSL
* libsodium
* make

### Build

```bash
git clone https://github.com/yourusername/ravencrypt.git
cd ravencrypt
make
```

### Run Tests and Benchmark

```bash
make test       # Run unit tests
make bench      # Run performance benchmarks
make test_hybrid # Run hybrid encryption tests
```

---

## Usage

### Basic Encryption and Decryption Example

```c
#include "ravencrypt.h"

int main() {
    raven_key_t key = {...}; // Set up your key here
    uint8_t plaintext[] = "Hello, Ravencrypt!";
    size_t plaintext_len = sizeof(plaintext) - 1;

    raven_encrypted_t encrypted = {0};
    uint8_t decrypted[plaintext_len];
    size_t decrypted_len = 0;

    if (raven_encrypt(RAVEN_CIPHER_AES_GCM, plaintext, plaintext_len, &key, &encrypted) != RAVEN_OK) {
        // Handle error
    }

    if (raven_decrypt(RAVEN_CIPHER_AES_GCM,
                      encrypted.ciphertext,
                      encrypted.ciphertext_len,
                      encrypted.mac,
                      encrypted.nonce,
                      &key,
                      decrypted,
                      &decrypted_len) != RAVEN_OK) {
        // Handle error
    }

    // Use decrypted data
}
```

---

## API Functions

* `raven_encrypt(cipher, plaintext, plaintext_len, key, encrypted_out)`
* `raven_decrypt(cipher, ciphertext, ciphertext_len, mac, nonce, key, decrypted_out, &decrypted_len)`
* `raven_kdf_argon2(password, password_len, salt, salt_len, out_key, out_key_len)`
* `raven_kdf_hkdf(ikm, ikm_len, salt, salt_len, info, info_len, out_key, out_key_len)`
* `raven_hybrid_encrypt(plaintext, plaintext_len, key1, key2, hybrid_encrypted_out)`
* `raven_hybrid_decrypt(hybrid_encrypted, key1, key2, decrypted_out, &decrypted_len)`

For detailed information, see the `include/ravencrypt.h` header file.

---

## Benchmark

The benchmark tool measures encryption and decryption time on 1MB of random data.
Run it with:

```bash
make bench
```

Performance results may vary depending on your hardware.

---

## Contributing

Ravencrypt is open source, and contributions are welcome! Please:

* Report issues or suggestions on the [GitHub Issues page](https://github.com/yourusername/ravencrypt/issues)
* Fork the repo, implement your changes, and submit a pull request
* Follow coding standards and include tests where applicable

---

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.

---

> **Note:** Ravencrypt is developed for research and educational purposes. Please thoroughly test and review before using in production or critical systems.