/*
 * ============================================================================
 *  vfs_core.c — Virtual Vault File System Core Implementation
 *  Standard : C99 / POSIX compliant
 * ============================================================================
 */
#define _POSIX_C_SOURCE 200112L
#include "vfs_core.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <errno.h>
#include <sodium.h>

/* XChaCha20-Poly1305 MAC tag length (16 bytes) */
#define XCHACHA_TAGLEN crypto_aead_xchacha20poly1305_ietf_ABYTES

/* 
 * Packed binary header structure for persistent storage layout.
 * Pragmatic packing enforces exact byte alignment without compiler padding.
 */
#pragma pack(push, 1)
typedef struct {
    char             magic[4];                                            /* Magic bytes identifier */
    uint8_t          version_major;                                       /* Application major version */
    uint8_t          version_minor;                                       /* Application minor version */
    uint64_t         ops;                                                 /* Argon2id CPU limit */
    uint64_t         mem;                                                 /* Argon2id RAM limit */
    uint64_t         payload_sz;                                          /* Payload length in bytes */
    unsigned char    salt[crypto_pwhash_SALTBYTES];                        /* Argon2id salt (16 bytes) */
    unsigned char    nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES]; /* Unique AEAD nonce (24 bytes) */
    unsigned char    hash[crypto_hash_sha256_BYTES];                      /* SHA-256 payload hash */
} CEF2HeaderPacked;
#pragma pack(pop)

/* Internal vault instance maintained in locked memory */
struct vfs_vault {
    unsigned char      *payload;             /* Locked payload buffer pointer */
    size_t              payload_sz;          /* Size of unencrypted payload */
    char                magic[4];            /* Format signature */
    uint8_t             version_major;       
    uint8_t             version_minor;       
    unsigned char       salt[crypto_pwhash_SALTBYTES];
    unsigned long long  ops;                 
    size_t              mem;                 
    bool                use_random_padding;  /* CSPRNG padding enabled flag */
};

static int g_sodium = 0; /* Global runtime status flag */

vfs_result vfs_check_runtime_environment(void) {
    if (sodium_init() < 0) return VFS_ERR_LIB_VERSION;
    if (SODIUM_LIBRARY_VERSION_MAJOR < 10) return VFS_ERR_LIB_VERSION;
    g_sodium = 1;
    return VFS_OK;
}

static void ensure_init(void) {
    if (!g_sodium) vfs_check_runtime_environment();
}

const char *vfs_result_str(vfs_result r) {
    switch (r) {
        case VFS_OK:                  return "operation completed successfully";
        case VFS_ERR_BADARGS:         return "invalid arguments supplied";
        case VFS_ERR_ALLOC:           return "memory allocation failed";
        case VFS_ERR_IO:              return "input/output error";
        case VFS_ERR_SIGNATURE:       return "invalid or mismatched file magic signature";
        case VFS_ERR_AUTH:            return "authentication failed (incorrect password or corrupt data)";
        case VFS_ERR_KDF:             return "key derivation function error";
        case VFS_ERR_WRITE:           return "file write error";
        case VFS_ERR_VERSION_MISMATCH:return "unsupported file version (incompatible version)";
        case VFS_ERR_LIB_VERSION:     return "unsupported libsodium version";
        case VFS_ERR_HEADER_INVALID:  return "invalid header: KDF parameters exceed safe limits";
        case VFS_ERR_INVALID_SIZE:    return "invalid size: payload/ciphertext beyond representable bound";
        default:                      return "unknown result code";
    }
}

void vfs_sanitize(char *dst, const char *src, size_t dst_size) {
    if (!dst || dst_size == 0) return;
    if (!src) { dst[0] = '\0'; return; }
    size_t i = 0;
    while (src[i] != '\0' && i < dst_size - 1) {
        unsigned char c = (unsigned char)src[i];
        /* Sanitises non-printable control characters */
        dst[i] = (c >= 32 && c <= 126) ? (char)c : '?';
        i++;
    }
    dst[i] = '\0';
}

VaultConfig vfs_config_default(const char magic[4], size_t payload_size) {
    VaultConfig cfg;
    memset(&cfg, 0, sizeof cfg);
    if (magic) memcpy(cfg.magic, magic, 4);
    else memcpy(cfg.magic, "CEF2", 4);
    
    cfg.version_major       = 1;
    cfg.version_minor       = 0;
    cfg.min_compat_major    = 1;
    cfg.payload_size        = (payload_size > 0) ? payload_size : (10ULL * 1024ULL * 1024ULL);
    /* FIX #6 (P1): default KDF strength aligned with libsodium MILD baseline
     * (3 ops / 64 MiB) instead of the previous 16 MiB floor. */
    cfg.ops_limit           = VFS_POLICY_MIN_OPS;
    cfg.mem_limit           = VFS_POLICY_MIN_MEM;
    cfg.use_random_padding  = true;
    return cfg;
}

/* Performs robust stream reading until the requested byte count is satisfied */
static bool rd_all(FILE *f, void *buf, size_t n) {
    if (n == 0) return true;
    return fread(buf, 1, n, f) == n && ferror(f) == 0;
}

/* Writes data to low-level file descriptors while handling interrupt signals */
static bool wr_all_fd(int fd, const void *buf, size_t n) {
    const unsigned char *p = (const unsigned char *)buf;
    size_t off = 0;
    while (off < n) {
        ssize_t w = write(fd, p + off, n - off);
        if (w < 0) { if (errno == EINTR) continue; return false; }
        if (w == 0) return false;
        off += (size_t)w;
    }
    return true;
}

vfs_result vfs_inspect_file(const char *path, VaultHeaderInfo *out_info) {
    if (!path || !out_info) return VFS_ERR_BADARGS;
    ensure_init();

    FILE *f = fopen(path, "rb");
    if (!f) return VFS_ERR_IO;

    CEF2HeaderPacked header;
    if (!rd_all(f, &header, sizeof header)) {
        fclose(f);
        return VFS_ERR_IO;
    }
    fclose(f);

    /* Extracts metadata attributes without executing key derivation */
    memcpy(out_info->magic, header.magic, 4);
    out_info->version_major = header.version_major;
    out_info->version_minor = header.version_minor;
    out_info->payload_size  = (size_t)header.payload_sz;
    out_info->ops_limit     = header.ops;
    out_info->mem_limit     = (size_t)header.mem;

    return VFS_OK;
}

Vault *vfs_create(const VaultConfig *config, vfs_result *out_err) {
    ensure_init();
    if (g_sodium != 1) { if (out_err) *out_err = VFS_ERR_LIB_VERSION; return NULL; }

    VaultConfig cfg = config ? *config : vfs_config_default("CEF2", 0);
    if (cfg.payload_size == 0) { if (out_err) *out_err = VFS_ERR_BADARGS; return NULL; }

    /* Allocates memory pages locked against swapping via sodium_malloc */
    Vault *v = (Vault *)sodium_malloc(sizeof *v);
    if (!v) { if (out_err) *out_err = VFS_ERR_ALLOC; return NULL; }
    memset(v, 0, sizeof *v);

    v->payload = (unsigned char *)sodium_malloc(cfg.payload_size);
    if (!v->payload) {
        sodium_free(v);
        if (out_err) *out_err = VFS_ERR_ALLOC;
        return NULL;
    }

    memcpy(v->magic, cfg.magic, 4);
    v->version_major      = cfg.version_major;
    v->version_minor      = cfg.version_minor;
    v->payload_sz         = cfg.payload_size;
    v->ops                = cfg.ops_limit;
    v->mem                = cfg.mem_limit;
    v->use_random_padding = cfg.use_random_padding;

    /* Generates cryptographically secure random bytes for salt creation */
    randombytes_buf(v->salt, sizeof v->salt);

    /* Fills memory buffer with CSPRNG noise to mitigate size analysis */
    if (v->use_random_padding) {
        randombytes_buf(v->payload, v->payload_sz);
    } else {
        memset(v->payload, 0, v->payload_sz);
    }

    if (out_err) *out_err = VFS_OK;
    return v;
}

Vault *vfs_open(const char *path, const char *password, const char expected_magic[4],
                uint8_t min_compat_major, VaultHeaderInfo *out_info, vfs_result *out_err) {
    if (!path || !password) { if (out_err) *out_err = VFS_ERR_BADARGS; return NULL; }
    ensure_init();
    if (g_sodium != 1) { if (out_err) *out_err = VFS_ERR_LIB_VERSION; return NULL; }

    FILE *f = fopen(path, "rb");
    if (!f) { if (out_err) *out_err = VFS_ERR_IO; return NULL; }

    CEF2HeaderPacked header;
    if (!rd_all(f, &header, sizeof header)) {
        fclose(f); if (out_err) *out_err = VFS_ERR_IO; return NULL;
    }

    /* Validates ecosystem signature identifier */
    if (expected_magic && memcmp(header.magic, expected_magic, 4) != 0) {
        fclose(f); if (out_err) *out_err = VFS_ERR_SIGNATURE; return NULL;
    }

    /* Enforces backward version compatibility constraints */
    if (min_compat_major > 0 && header.version_major < min_compat_major) {
       fclose(f); if (out_err) *out_err = VFS_ERR_VERSION_MISMATCH; return NULL;
    }

    /* FIX #2 (P0): the on-disk KDF parameters are attacker-controlled. Reject any
     * header that would force an unbounded Argon2id derivation (CPU/RAM DoS)
     * BEFORE crypto_pwhash() is ever invoked. A malicious .cef2 can therefore
     * never make a victim that opens it burn unbounded time or memory. */
    if (header.ops == 0 || header.ops > VFS_ARGON2_MAX_OPS ||
       header.mem == 0 || header.mem > VFS_ARGON2_MAX_MEM_BYTES) {
       fclose(f); if (out_err) *out_err = VFS_ERR_HEADER_INVALID; return NULL;
    }

    /* FIX #5 (P1): guard the ciphertext-allocation total (payload + AEAD tag)
     * against integer wrap, which would otherwise yield a tiny malloc and a
     * subsequent heap over-read. */
    if (header.payload_sz > (uint64_t)(SIZE_MAX - XCHACHA_TAGLEN)) {
       fclose(f); if (out_err) *out_err = VFS_ERR_INVALID_SIZE; return NULL;
    }

    size_t payload_sz = (size_t)header.payload_sz;
    Vault *v = (Vault *)sodium_malloc(sizeof *v);
    if (!v) { fclose(f); if (out_err) *out_err = VFS_ERR_ALLOC; return NULL; }
    memset(v, 0, sizeof *v);

    v->payload = (unsigned char *)sodium_malloc(payload_sz);
    if (!v->payload) {
        sodium_free(v); fclose(f);
        if (out_err) *out_err = VFS_ERR_ALLOC; return NULL;
    }

    memcpy(v->magic, header.magic, 4);
    v->version_major = header.version_major;
    v->version_minor = header.version_minor;
    v->payload_sz    = payload_sz;
    v->ops           = header.ops;
    v->mem           = (size_t)header.mem;
    memcpy(v->salt, header.salt, sizeof v->salt);

    /* Reads encrypted payload and authentication tag */
    size_t ctsz = payload_sz + XCHACHA_TAGLEN;
    unsigned char *ct = (unsigned char *)malloc(ctsz);
    if (!ct || !rd_all(f, ct, ctsz)) {
        if (ct) free(ct);
        sodium_free(v->payload); sodium_free(v);
        fclose(f); if (out_err) *out_err = VFS_ERR_IO; return NULL;
    }
    fclose(f);

    unsigned char key[32] = {0}, want_hash[32] = {0};
    vfs_result res = VFS_ERR_AUTH;

    /* Derives symmetric key using Argon2id algorithm */
    if (password[0] != '\0' &&
        crypto_pwhash(key, sizeof key, password, strlen(password), v->salt,
                      v->ops, v->mem, crypto_pwhash_ALG_ARGON2ID13) == 0) {
        
        /* Decrypts and authenticates payload using XChaCha20-Poly1305 AEAD */
        if (crypto_aead_xchacha20poly1305_ietf_decrypt(
                v->payload, NULL, NULL, ct, ctsz, NULL, 0, header.nonce, key) == 0) {
            
            /* Performs secondary SHA-256 integrity check */
            crypto_hash_sha256(want_hash, v->payload, payload_sz);
            if (memcmp(header.hash, want_hash, sizeof want_hash) == 0) {
                res = VFS_OK;
            }
        }
    }

    /* Executes immediate zeroisation of sensitive key material */
    sodium_memzero(key, sizeof key);
    sodium_memzero(want_hash, sizeof want_hash);
    free(ct);

    if (res != VFS_OK) {
        /* FIX #1 (P0): on an authentication failure the payload buffer may still
         * hold freshly-decrypted plaintext (e.g. AEAD tag verified but the
         * secondary SHA-256 check diverged). Zeroise EVERY exit-path sensitive
         * region BEFORE freeing so plaintext never lingers in a freed page/struct
         * that a later sodium_malloc may reuse. */
       if (v->payload) {
           sodium_memzero(v->payload, v->payload_sz);
           sodium_free(v->payload);
       }
       sodium_memzero(v->salt, sizeof v->salt);
       sodium_memzero(v, sizeof *v);
       sodium_free(v);
       if (out_err) *out_err = res;
       return NULL;
     }

    if (out_info) {
        memcpy(out_info->magic, v->magic, 4);
        out_info->version_major = v->version_major;
        out_info->version_minor = v->version_minor;
        out_info->payload_size  = v->payload_sz;
        out_info->ops_limit     = v->ops;
        out_info->mem_limit     = v->mem;
    }

    if (out_err) *out_err = VFS_OK;
    return v;
}

vfs_result vfs_save(Vault *v, const char *path, const char *password) {
    if (!v || !path || !password) return VFS_ERR_BADARGS;
    ensure_init();
    if (g_sodium != 1) return VFS_ERR_LIB_VERSION;

    unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
    unsigned char ch[crypto_hash_sha256_BYTES];
    unsigned char key[32] = {0};

    /* Generates unique nonce and computes payload checksum prior to encryption */
    randombytes_buf(nonce, sizeof nonce);
    crypto_hash_sha256(ch, v->payload, v->payload_sz);

    CEF2HeaderPacked header;
    memset(&header, 0, sizeof header);
    memcpy(header.magic, v->magic, 4);
    header.version_major = v->version_major;
    header.version_minor = v->version_minor;
    header.ops           = v->ops;
    header.mem           = v->mem;
    header.payload_sz    = v->payload_sz;
    memcpy(header.salt,  v->salt,  sizeof v->salt);
    memcpy(header.nonce, nonce,   sizeof nonce);
    memcpy(header.hash,  ch,      sizeof ch);

    /* Derives symmetric encryption key via Argon2id */
    if (crypto_pwhash(key, sizeof key, password, strlen(password),
                     v->salt, v->ops, v->mem, crypto_pwhash_ALG_ARGON2ID13) != 0) {
       return VFS_ERR_KDF;
    }

    /* FIX #5 (P1): guard the ciphertext buffer total (payload + AEAD tag) against
     * integer wrap before the allocation; a wrapped value would under-allocate and
     * lead to a heap over-read on the subsequent AEAD encrypt. */
    if (v->payload_sz > (size_t)(SIZE_MAX - XCHACHA_TAGLEN)) {
       sodium_memzero(key, sizeof key);
       return VFS_ERR_INVALID_SIZE;
    }
    size_t ctsz = v->payload_sz + XCHACHA_TAGLEN;
    unsigned char *ct = (unsigned char *)malloc(ctsz);
    if (!ct) {
        sodium_memzero(key, sizeof key);
        return VFS_ERR_ALLOC;
    }

    /* Encrypts payload with XChaCha20-Poly1305 AEAD cipher */
    unsigned long long cllen = 0;
    if (crypto_aead_xchacha20poly1305_ietf_encrypt(
            ct, &cllen, v->payload, v->payload_sz, NULL, 0, NULL, nonce, key) != 0) {
        free(ct);
        sodium_memzero(key, sizeof key);
        return VFS_ERR_WRITE;
    }
    
    /* Zeroises key buffer immediately following encryption */
    sodium_memzero(key, sizeof key);

    /* \
     * Atomic persistence sequence (FIX #3/#4 P1):
     *  - deterministic tmp name "path.tmp", but:
     *      * unlink any stale .tmp from a previously-aborted run first;
     *      * open the tmp with O_EXCL so we NEVER follow a symlink an
     *        attacker may have planted at "path.tmp" (symlink-redirection
     *        / overwrite-via-symlink attack is defeated);
     *      * write header + ciphertext, fsync the *file* (durably flushed
     *        to the device), then atomically rename(tmp -> path);
     *      * fsync the *parent directory* so the rename directory entry is
     *        itself durable across a power loss, then close every fd.
     *   A complete, authenticated vault file is the only thing that ever
     *   replaces the live "path".
     */
    char tmp[4096];
    if (strlen(path) + 4 >= sizeof tmp) {
        free(ct);
        return VFS_ERR_BADARGS;   /* path too long for the tmp buffer */
    }
    snprintf(tmp, sizeof tmp, "%s.tmp", path);

    unlink(tmp);   /* clear a stale .tmp left by a prior aborted write */

    int tmpfd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_EXCL, 0600);
    if (tmpfd < 0) {
        free(ct);
        return VFS_ERR_WRITE;
      }

      /* fsync the parent directory after rename so the directory entry
       * (the rename itself) is durably journaled on power loss. */
    char dircopy[4096];
    int  parent_fd = -1;
    strncpy(dircopy, path, sizeof dircopy - 1);
    dircopy[sizeof dircopy - 1] = '\0';
    char *slash = strrchr(dircopy, '/');
    if (slash) {
        *slash = '\0';
        parent_fd = open(dircopy[0] ? dircopy : ".", O_RDONLY);
    } else {
        parent_fd = open(".", O_RDONLY);
      }

    vfs_result res = VFS_ERR_WRITE;
    if (wr_all_fd(tmpfd, &header, sizeof header) &&
        wr_all_fd(tmpfd, ct, cllen) &&
        fsync(tmpfd) == 0) {
        if (rename(tmp, path) == 0) {
            if (parent_fd >= 0) fsync(parent_fd);
            res = VFS_OK;
          }
      }

    if (res != VFS_OK) unlink(tmp);
    close(tmpfd);
    if (parent_fd >= 0) close(parent_fd);
    free(ct);
    return res;
    }

void vfs_destroy(Vault *v) {
    if (!v) return;
    if (v->payload) {
        /* Applies zeroisation to clear payload buffer prior to releasing memory */
        sodium_memzero(v->payload, v->payload_sz);
        sodium_free(v->payload);
    }
    sodium_memzero(v->salt, sizeof v->salt);
    sodium_free(v);
}

void *vfs_payload_ptr(Vault *v) {
    return v ? v->payload : NULL;
}

size_t vfs_payload_size(const Vault *v) {
    return v ? v->payload_sz : 0;
}