# libvfs — Virtual Vault File System Engine

[![Standard](https://img.shields.io/badge/C--Standard-C99-blue.svg)](https://en.cppreference.com/w/c/99)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-macOS%20%7C%20Linux%20%7C%20Windows-lightgrey.svg)](#building)

**`libvfs` is a high-performance, minimalist C99 static library engineered for secure, atomic vault storage. Designed for privacy-sensitive applications and immutable operating system architectures, `libvfs` encapsulates binary payloads within authenticated encrypted containers with zero-trace memory hygiene.**

---

## Cryptographic Architecture

The core security model relies on industry-standard cryptographic primitives provided by `libsodium`:

* **Key Derivation Function (KDF):** Argon2id (`crypto_pwhash_ALG_ARGON2ID13`) for GPU-resistant key strengthening.
* **Authenticated Encryption (AEAD):** XChaCha20-Poly1305 (`crypto_aead_xchacha20poly1305_ietf`) for confidentiality and authenticity.
* **Integrity Check:** SHA-256 payload checksum validation prior to and post-decryption.
* **Memory Safety:** Page-locked memory allocation via `sodium_malloc()` combined with strict `sodium_memzero()` zeroisation on destruction.
* **Atomic Persistence:** Temporary file writes backed by POSIX `fsync()` and atomic system calls to prevent corruption during power loss.


## Requirements

* **C Compiler:** `clang` (recommended for macOS) or `gcc` (version 4.9+).
* **C Standard:** C99 or later (`-std=c99`).
* **Dependencies:** `libsodium` (version 1.0.18 or higher).

### Installing Dependencies

#### macOS (via Homebrew)
```bash
brew install libsodium
```

Ubuntu / Debian
```Bash
sudo apt-get update
sudo apt-get install libsodium-dev build-essential
```

Building the Library

**The project includes a platform-aware Makefile that automatically detects the host OS and architecture to apply optimal compilation flags (e.g. ARM64 targeting on Apple Silicon or native vector instructions on Linux).**


To compile the static library (libvfs.a):
```Bash
make
```
To clean build artefacts:
```Bash
make clean
```

## Usage Guide

### 1. Linking libvfs to Your Application
Include vfs_core.h in your source file and link against libvfs.a and libsodium:
Bash
gcc -std=c99 main.c -I/path/to/include libvfs.a -lsodium -o my_app

### 2. Integration Example
The following minimal example demonstrates creating, populating, persisting, and zeroising an encrypted vault instance:
```C
#include <stdio.h>
#include <string.h>
#include "vfs_core.h"

int main(void) {
    vfs_result err;

    /* 1. Verify runtime environment and libsodium availability */
    if (vfs_check_runtime_environment() != VFS_OK) {
        fprintf(stderr, "Error: Runtime environment check failed.\n");
        return 1;
    }

    /* 2. Initialise default configuration for a 1 MiB vault */
    VaultConfig config = vfs_config_default("CEF2", 1024 * 1024);
    
    Vault *vault = vfs_create(&config, &err);
    if (!vault) {
        fprintf(stderr, "Error creating vault: %s\n", vfs_result_str(err));
        return 1;
    }

    /* 3. Access secure memory buffer and write payload */
    char *data = (char *)vfs_payload_ptr(vault);
    snprintf(data, vfs_payload_size(vault), "Sensitive cryptographic payload data.");

    /* 4. Atomically encrypt and persist vault to disk */
    err = vfs_save(vault, "secure_store.cef2", "MasterPassphrase123!");
    if (err != VFS_OK) {
        fprintf(stderr, "Error saving vault: %s\n", vfs_result_str(err));
        vfs_destroy(vault);
        return 1;
    }

    /* 5. Clear memory buffers and release RAM */
    vfs_destroy(vault);
    printf("Vault successfully encrypted and persisted.\n");

    return 0;
}
```

|             Function            |                              Description                              |
|:-------------------------------:|:---------------------------------------------------------------------:|
| vfs_check_runtime_environment() | Validates system environment and libsodium initialization.            |
| vfs_config_default()            | Returns a standard VaultConfig structure with secure defaults.        |
| vfs_create()                    | Allocates a new vault in locked RAM with CSPRNG noise padding.        |
| vfs_open()                      | Authenticates, decrypts, and verifies a .cef2 container into RAM.     |
| vfs_save()                      | Encrypts payload and executes atomic write to storage via fsync.      |
| vfs_inspect_file()              | Reads binary header metadata without executing key derivation.        |
| vfs_destroy()                   | Applies sodium_memzero() to sensitive data and frees memory.          |
| vfs_payload_ptr()               | Returns a direct pointer to the unencrypted payload buffer in memory. |

---

## Advanced Usage & Custom Security Policies

### 1. Customising KDF Parameters and Magic Headers

For high-security environments, application developers can override default parameters to increase GPU-attack resistance or enforce custom application magic bytes.

```c
#include <stdio.h>
#include <string.h>
#include "vfs_core.h"

int main(void) {
    vfs_result err;

    /* Define custom configuration with application-specific magic header */
    VaultConfig config = {
        .magic              = {'P', 'A', 'S', 'S'},          /* Application identifier */
        .version_major      = 1,
        .version_minor      = 2,
        .min_compat_major   = 1,
        .payload_size       = 50 * 1024 * 1024,              /* 50 MiB payload */
        .ops_limit          = 5ULL,                          /* Increased CPU iterations */
        .mem_limit          = 64ULL * 1024ULL * 1024ULL,     /* 64 MiB RAM limit for Argon2id */
        .use_random_padding = true                           /* Obfuscate unused payload space */
    };

    Vault *vault = vfs_create(&config, &err);
    if (!vault) {
        fprintf(stderr, "Vault creation failed: %s\n", vfs_result_str(err));
        return 1;
    }

    /* Perform atomic save with custom parameters */
    err = vfs_save(vault, "passwords.vault", "UltraSecurePassphrase!");
    vfs_destroy(vault);

    return (err == VFS_OK) ? 0 : 1;
}
```

### 2. Header Inspection Without Key Derivation
To inspect container parameters (such as memory limits, iterations, or magic bytes) without prompting for passwords or executing resource-heavy KDF iterations, use vfs_inspect_file():

```C
#include <stdio.h>
#include "vfs_core.h"

int main(void) {
    VaultHeaderInfo info;
    vfs_result res = vfs_inspect_file("passwords.vault", &info);

    if (res == VFS_OK) {
        printf("Magic Signature : %.4s\n", info.magic);
        printf("Format Version  : %u.%u\n", info.version_major, info.version_minor);
        printf("Payload Capacity: %zu bytes\n", info.payload_size);
        printf("Argon2id Memory : %zu MiB\n", info.mem_limit / (1024 * 1024));
    } else {
        fprintf(stderr, "Inspection failed: %s\n", vfs_result_str(res));
    }

    return 0;
}
````

## Development Note & AI Disclosure

This project was developed using a **Live Coding / Human-in-the-Loop** approach with **AI** assistance for code generation, boilerplate streamlining, and rapid prototyping.

However, the core security model, the vault structure layout (`.cef`), the memory hygiene policies, and the structural validation logic were designed, directed, and architected entirely by the creator. **While some implementation details and initial validations may be in an early/preliminary stage, the architectural vision and threat model are strictly human-driven.**

## Call for Security Audits & The `libvfs` Breaking Challenge

The core goal of `libvfs` is to provide uncompromising, zero-trust memory and storage security. With the release of **v1.0.0**, we actively invite security researchers, developers, and cryptanalysts to audit, stress-test, and attempt to break this engine.

### 🚩 The Challenge: `challenge_1.cef2`
Included in the repository is a live test vault file: `challenge_1.cef2`. 

I challenge the community to target this engine through two distinct paths:

1. **The Cryptographic / Extraction Challenge:** 
   Extract the secret payload stored inside `challenge_1.cef2` without knowing the master key. *(Successfully breaking the vault implies identifying a critical flaw in our key derivation, stream cipher execution, or header structure).*
2. **The Memory Safety & Robustness Challenge:** 
   Demonstrate a functional exploit in the C99 library itself — such as a `sodium_malloc` bypass, un-zeroed memory remnants (`sodium_memzero` omission), an unchecked memory allocation DoS vector, or an atomic persistence corruptor.

### 🏆 Hall of Fame & Recognition
Researchers who successfully demonstrate valid vulnerabilities or crack the challenge vault will be:
* Permanently featured in our **`HALL OF FAME.md`** and release documentation.
* Credited directly in official security advisories for the project.

If you discover a vulnerability, please submit a detailed **Security Advisory** or open an Issue with a reproducible Proof-of-Concept (PoC).

## License

**This project is licensed under the MIT License.**
