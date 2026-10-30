/*
 * ============================================================================
 *  vfs_core.h — Virtual Vault File System Engine (SDK)
 *  Standard : C99 / POSIX compliant (Optimised for Apple Silicon)
 *  Description: API interface for atomic encrypted vault operations.
 * ============================================================================
 */
#ifndef VFS_CORE_H
#define VFS_CORE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Core API version definitions */
#define VFS_CORE_VERSION_MAJOR 1
#define VFS_CORE_VERSION_MINOR 0

/* Security threshold parameters for Argon2id KDF.
 * Defaults align with libsodium MILD baseline (3 ops / 64 MiB) so a
 * vfs_config_default() vault is at least as strong as crypto_pwhash MILD. */
#define VFS_POLICY_MIN_OPS 3ULL                              /* Minimum CPU iterations */
#define VFS_POLICY_MIN_MEM (64ULL * 1024ULL * 1024ULL)       /* Default memory (64 MiB ~ MILD) */

/* FIX #2 (P0): hard anti-DoS upper bounds on attacker-controlled KDF parameters
 * read from the .cef2 header. Any vault requesting more is rejected BEFORE
 * crypto_pwhash() is ever invoked, so a malicious file cannot force a CPU/RAM
 * exhaustion DoS on the victim that calls vfs_open(). */
#define VFS_ARGON2_MAX_OPS       1000000ULL                 /* 1,000,000 iterations cap */
#define VFS_ARGON2_MAX_MEM_BYTES (256ULL * 1024ULL * 1024ULL) /* 256 MiB memory cap */

/**
 * @brief Return codes for all library functions.
 */
typedef enum {
    VFS_OK = 0,               /**< Operation completed successfully. */
    VFS_ERR_BADARGS,          /**< Invalid parameters supplied to function. */
    VFS_ERR_ALLOC,            /**< Allocation of secure memory failed (sodium_malloc). */
    VFS_ERR_IO,               /**< Input/Output error during file operation. */
    VFS_ERR_SIGNATURE,        /**< Invalid or mismatched header signature (Magic Bytes). */
    VFS_ERR_AUTH,             /**< Authentication failure: incorrect passphrase or corrupted payload. */
    VFS_ERR_KDF,              /**< Key derivation failure during Argon2id execution. */
    VFS_ERR_WRITE,            /**< Error encountered during atomic file persistence. */
    VFS_ERR_VERSION_MISMATCH, /**< Vault format version is incompatible with minimum requirement. */
    VFS_ERR_LIB_VERSION,      /**< Installed libsodium version does not meet requirements. */
    VFS_ERR_HEADER_INVALID,   /**< FIX #2 (P0): on-disk KDF parameters exceed anti-DoS bounds. */
    VFS_ERR_INVALID_SIZE      /**< FIX #5 (P1): payload/ciphertext size exceeds a representable bound. */
} vfs_result;

/**
 * @brief Configuration structure for initialising a new vault instance.
 */
typedef struct {
    char                magic[4];           /**< 4-byte header identifier (e.g. "CEF2"). */
    uint8_t             version_major;      /**< Major format version of the application. */
    uint8_t             version_minor;      /**< Minor format version of the application. */
    uint8_t             min_compat_major;   /**< Minimum compatible major version for opening. */
    size_t              payload_size;       /**< Fixed payload buffer size in bytes. */
    unsigned long long  ops_limit;          /**< Iteration count for Argon2id key derivation. */
    size_t              mem_limit;          /**< Memory allocation for Argon2id in bytes. */
    bool                use_random_padding; /**< Fills unallocated space with CSPRNG noise. */
} VaultConfig;

/**
 * @brief Header information structure retrieved without decryption.
 */
typedef struct {
    char                magic[4];
    uint8_t             version_major;
    uint8_t             version_minor;
    size_t              payload_size;
    unsigned long long  ops_limit;
    size_t              mem_limit;
} VaultHeaderInfo;

/* Opaque structure pointer for in-memory vault representation */
typedef struct vfs_vault Vault;

/* ============================================================================
 *  API FUNCTION PROTOTYPES
 * ============================================================================
 */

/** @brief Initialises the libsodium runtime and verifies version compatibility. */
vfs_result  vfs_check_runtime_environment(void);

/** @brief Converts an error code into a human-readable string representation. */
const char *vfs_result_str(vfs_result r);

/** @brief Sanitises input strings to remove non-printable characters. */
void        vfs_sanitize(char *dst, const char *src, size_t dst_size);

/** @brief Generates a default security configuration for a specified vault size. */
VaultConfig vfs_config_default(const char magic[4], size_t payload_size);

/** @brief Inspects vault metadata from disk without performing key derivation. */
vfs_result  vfs_inspect_file(const char *path, VaultHeaderInfo *out_info);

/** @brief Allocates and initialises a new vault in locked RAM. */
Vault      *vfs_create(const VaultConfig *config, vfs_result *out_err);

/** @brief Authenticates, decrypts, and verifies a vault from persistent storage into RAM. */
Vault      *vfs_open(const char *path, const char *password, const char expected_magic[4],
                     uint8_t min_compat_major, VaultHeaderInfo *out_info, vfs_result *out_err);

/** @brief Encrypts and atomically writes the vault to disk via fsync and renaming. */
vfs_result  vfs_save(Vault *v, const char *path, const char *password);

/** @brief Erases sensitive payload data using zeroisation and frees allocated RAM. */
void        vfs_destroy(Vault *v);

/** @brief Returns a direct pointer to the decrypted memory buffer. */
void       *vfs_payload_ptr(Vault *v);

/** @brief Returns the total size of the vault payload in bytes. */
size_t      vfs_payload_size(const Vault *v);

#endif /* VFS_CORE_H */