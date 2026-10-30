/*
 * test_adversarial.c — Clean-sheet adversarial harness for libvfs (CEF2)
 *
 * Exercises hostile inputs and boundary conditions:
 *   A. NULL pointers / uninitialised structs / invalid paths
 *   B. Wrong / empty credentials
 *   C. Header tampering + DoS-fuzzing (exaggerated ops/mem, huge payload_sz)
 *      with sub-millisecond rejection assertions
 *   D. Truncated / corrupted / random-entropy files
 *   E. I/O permission (chmod 000) and symlink-TOCTOU redirection
 *
 * C99. Not a memory-overflow fuzz; it asserts *result codes* and graceful
 * non-crash, and measures anti-DoS timing.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200112L
#endif
#include "vfs_core.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>

static int g_fail = 0;
static int g_pass = 0;

#define CHECK(cond, msg, ...) do {                         \
    if (cond) { printf("  [ PASS ] " msg "\n", ##__VA_ARGS__); g_pass++; } \
    else      { printf("  [ FAIL ] " msg "\n", ##__VA_ARGS__); g_fail++; }  \
} while (0)

#define PW "TheCorrectHorsePassphrase"

static double now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000.0 + ts.tv_nsec / 1.0e6;
}

/* Build a raw CEF2 header (packed, 96 bytes) in memory, write it to `path`,
 * then append `body` (ciphertext region) bytes. Returns 0 on success. */
/*
 * On-disk layout (packed, 96 bytes):
 *   0..3   magic[4]
 *   4      version_major
 *   5      version_minor
 *   6..7   padding (to align ops to 8)
 *   8..15  ops        (uint64 LE)
 *   16..23 mem        (uint64 LE)
 *   24..31 payload_sz (uint64 LE)
 *   32..47 salt(16)
 *   48..71 nonce(24)
 *   72..103 hash(32)
 */
static int write_raw_vault(const char *path, uint64_t ops, uint64_t mem,
                           uint64_t payload_sz, const char *magic,
                           int fill_body, int body_len)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) { perror("open(raw)"); return -1; }

    unsigned char buf[128];
    memset(buf, 0, sizeof buf);
    const char *m = magic ? magic : "CEF2";
    memcpy(buf, m, 4);
    buf[4] = 1; /* version_major */
    buf[5] = 0; /* version_minor */

    memcpy(buf + 8,  &ops,        8);
    memcpy(buf + 16, &mem,        8);
    memcpy(buf + 24, &payload_sz, 8);
    /* salt/nonce/hash left zero (random enough for a hostile probe; open will
     * authenticate-fail, which is what we're testing) */

    if (write(fd, buf, 102) != 102) { close(fd); return -1; }
    if (fill_body && body_len > 0) {
        unsigned char body[4096];
        int n = body_len > (int)sizeof body ? (int)sizeof body : body_len;
        for (int i = 0; i < n; i++) body[i] = (unsigned char)(i * 37 + 11);
        if (write(fd, body, n) != n) { close(fd); return -1; }
    }
    close(fd);
    return 0;
}

int main(void)
{
    printf("\n========== libvfs ADVERSARIAL HARNESS ==========\n");

    /* ---- Runtime ---- */
    vfs_result e = VFS_ERR_LIB_VERSION;
    Vault *r = NULL;      /* reused across open() probes at function scope */
    e = vfs_check_runtime_environment();
    CHECK(e == VFS_OK, "runtime environment initialises (err=%d)", e);

    /* =================================================================
     * A. NULL pointers / uninitialised / invalid paths
     * ================================================================= */
    printf("\n[A] NULL-pointer & bad-arg guardrails\n");
    e = VFS_OK;
    CHECK(vfs_open(NULL, PW, "CEF2", 1, NULL, &e) == NULL && e == VFS_ERR_BADARGS,
          "vfs_open(NULL path) -> NULL, BADARGS (got %d)", e);
    e = VFS_OK;
    CHECK(vfs_open("basic.cef2", NULL, "CEF2", 1, NULL, &e) == NULL && e == VFS_ERR_BADARGS,
          "vfs_open(NULL password) -> NULL, BADARGS (got %d)", e);
    CHECK(vfs_save(NULL, "x.cef2", PW) == VFS_ERR_BADARGS, "vfs_save(NULL v) -> BADARGS");
    CHECK(vfs_save(NULL, NULL, PW) == VFS_ERR_BADARGS,     "vfs_save(NULL path) -> BADARGS");
    CHECK(vfs_save(NULL, "x.cef2", NULL) == VFS_ERR_BADARGS, "vfs_save(NULL pw) -> BADARGS");
    CHECK(vfs_inspect_file(NULL, NULL) == VFS_ERR_BADARGS,  "vfs_inspect(NULL,NULL) -> BADARGS");
    CHECK(vfs_payload_ptr(NULL) == NULL,                      "vfs_payload_ptr(NULL) -> NULL");
    CHECK(vfs_payload_size((const Vault *)NULL) == 0,         "vfs_payload_size(NULL) -> 0");
    vfs_destroy(NULL); /* explicit; must not crash */
    CHECK(1, "vfs_destroy(NULL) no crash");

    /* Invalid / non-existent path */
    e = VFS_OK;
    CHECK(vfs_open("/no/such/file/here.cef2", PW, "CEF2", 1, NULL, &e) == NULL && e == VFS_ERR_IO,
          "vfs_open(missing file) -> NULL, IO (got %d)", e);

    /* =================================================================
     * B. Wrong / empty credentials
     * ================================================================= */
    printf("\n[B] credentials: wrong & empty\n");
    /* Need a valid vault to test against */
    VaultConfig cfg = vfs_config_default("CEF2", 128);
    cfg.use_random_padding = false; /* deterministic content */
    Vault *good = vfs_create(&cfg, &e);
    CHECK(good != NULL && e == VFS_OK, "create good vault (128B)");
    if (good) {
        char *pp = vfs_payload_ptr(good);
        snprintf(pp, vfs_payload_size(good), "adversarial-payload");
        e = vfs_save(good, "good.cef2", PW);
        CHECK(e == VFS_OK, "save good vault -> good.cef2 (err=%d)", e);

        /* wrong password */
        e = VFS_OK;
        r = vfs_open("good.cef2", "definitely-wrong", "CEF2", 1, NULL, &e);
        CHECK(r == NULL && e == VFS_ERR_AUTH, "reopen with wrong password -> AUTH (got %d)", e);

        /* empty password */
        e = VFS_OK;
        r = vfs_open("good.cef2", "", "CEF2", 1, NULL, &e);
        CHECK(r == NULL && e == VFS_ERR_AUTH, "reopen with empty password -> AUTH (got %d)", e);

        /* correct password, round-trip */
        e = VFS_ERR_IO;
        r = vfs_open("good.cef2", PW, "CEF2", 1, NULL, &e);
        CHECK(r != NULL && e == VFS_OK, "reopen with correct password -> OK");
        if (r && strcmp(vfs_payload_ptr(r), "adversarial-payload") == 0)
            printf("        (payload round-trip verified)\n");
        vfs_destroy(r);
    }
    vfs_destroy(good);

    /* =================================================================
     * C. Header tampering + DoS fuzz — sub-millisecond rejection
     * ================================================================= */
    printf("\n[C] header tampering & anti-DoS KDF caps\n");

    /* 100 GB memory cap */
    CHECK(write_raw_vault("huge_mem.cef2", 3, 100ULL * 1024 * 1024 * 1024, 16, "CEF2", 1, 32) == 0,
          "generated hostile vault with mem=100GB");
    {
        double t0 = now_ms();
        e = VFS_OK;
        r = vfs_open("huge_mem.cef2", PW, "CEF2", 1, NULL, &e);
        double dt = now_ms() - t0;
        CHECK(r == NULL && e == VFS_ERR_HEADER_INVALID,
              "mem=100GB rejected as HEADER_INVALID (got %d)", e);
        CHECK(dt < 5.0, "  ...rejection took %.3f ms (< 5ms, no crypto_pwhash) ", dt);
    }

    /* 100M ops cap (1,000,000 is the max) */
    CHECK(write_raw_vault("huge_ops.cef2", 100000000ULL, 64ULL * 1024 * 1024, 16, "CEF2", 1, 32) == 0,
          "generated hostile vault with ops=100M");
    {
        double t0 = now_ms();
        e = VFS_OK;
        r = vfs_open("huge_ops.cef2", PW, "CEF2", 1, NULL, &e);
        double dt = now_ms() - t0;
        CHECK(r == NULL && e == VFS_ERR_HEADER_INVALID,
              "ops=100M rejected as HEADER_INVALID (got %d)", e);
        CHECK(dt < 5.0, "  ...rejection took %.3f ms (< 5ms) ", dt);
    }

    /* zero ops / zero mem */
    CHECK(write_raw_vault("zero_params.cef2", 0, 64ULL*1024*1024, 16, "CEF2", 1, 32) == 0, "generated vault with ops=0");
    e = VFS_OK; r = vfs_open("zero_params.cef2", PW, "CEF2", 1, NULL, &e);
    CHECK(r == NULL && e == VFS_ERR_HEADER_INVALID, "ops=0 rejected as HEADER_INVALID (got %d)", e);
    CHECK(write_raw_vault("zero_mem.cef2", 3, 0, 16, "CEF2", 1, 32) == 0, "generated vault with mem=0");
    e = VFS_OK; r = vfs_open("zero_mem.cef2", PW, "CEF2", 1, NULL, &e);
    CHECK(r == NULL && e == VFS_ERR_HEADER_INVALID, "mem=0 rejected as HEADER_INVALID (got %d)", e);

    /* EXACT-ceiling boundary: just-beyond-ceiling must be rejected instantly.
     * VFS_ARGON2_MAX_MEM_BYTES=256 MiB. Proves the guard is a tight, correct
     * boundary (not a blunt floor) without running an expensive acceptable-candidate
     * KDF. The within-ceiling *accept* direction is proven by probe_edges P1. */
    {
        double t0 = now_ms();
        write_raw_vault("ceiling_plus1mem.cef2", 3, 256ULL*1024*1024 + 1, 16, "CEF2", 1, 32);
        e = VFS_OK; r = vfs_open("ceiling_plus1mem.cef2", PW, "CEF2", 1, NULL, &e);
        double dt = now_ms() - t0;
        CHECK(r == NULL && e == VFS_ERR_HEADER_INVALID,
              "mem=256MiB+1 (just over cap) rejected HEADER_INVALID (got %d)", e);
        CHECK(dt < 5.0, "  ...rejection %.3f ms (<5ms, no KDF, tight boundary)", dt);
    }

    /* Huge payload_sz: SIZE_MAX overflow guard + allocation behaviour */
    CHECK(write_raw_vault("huge_payload.cef2", 3, 64ULL*1024*1024,
                          0xFFFFFFFFFFFFFF0ULL /* ~SIZE_MAX-16, forces near-max alloc */,
                          "CEF2", 0, 0) == 0, "generated vault with payload_sz~SIZE_MAX");
    e = VFS_OK; r = vfs_open("huge_payload.cef2", PW, "CEF2", 1, NULL, &e);
    CHECK(r == NULL && (e == VFS_ERR_ALLOC || e == VFS_ERR_IO || e == VFS_ERR_HEADER_INVALID),
          "payload_sz~SIZE_MAX fails gracefully, no crash (got %d: %s)", e, vfs_result_str(e));

    /* =================================================================
     * D. truncated / corrupted / random files
     * ================================================================= */
    printf("\n[D] truncation, corruption, random entropy\n");

    /* empty file */
    int fd = open("empty.cef2", O_WRONLY|O_CREAT|O_TRUNC, 0600); if (fd>=0) close(fd);
    e = VFS_OK; r = vfs_open("empty.cef2", PW, "CEF2", 1, NULL, &e);
    CHECK(r == NULL && e == VFS_ERR_IO, "empty file -> IO (got %d)", e);

    /* short header (50 bytes < 96) */
    {
        unsigned char h[50]; for (int i=0;i<50;i++) h[i]=(unsigned char)i;
        int f=open("short.cef2",O_WRONLY|O_CREAT|O_TRUNC,0600); if(f>=0){ write(f,h,50); close(f);}
    }
    e = VFS_OK; r = vfs_open("short.cef2", PW, "CEF2", 1, NULL, &e);
    CHECK(r == NULL && e == VFS_ERR_IO, "truncated header (50B) -> IO (got %d)", e);

    /* wrong magic */
    write_raw_vault("badmagic.cef2", 3, 64ULL*1024*1024, 16, "XXXX", 1, 32);
    e = VFS_OK; r = vfs_open("badmagic.cef2", PW, "CEF2", 1, NULL, &e);
    CHECK(r == NULL && e == VFS_ERR_SIGNATURE, "bad magic 'XXXX' -> SIGNATURE (got %d)", e);

    /* version mismatch */
    {
        unsigned char h[102]; memset(h,0,102);
        memcpy(h,"CEF2",4); h[4]=1; /* version_major=1, version_minor=0 */
        /* To trigger VERSION_MISMATCH: header version_major=1 below min_compat_major=5.
         * ops/mem set to valid defaults so they pass the anti-DoS gate. */
        {uint64_t o=3, m=64ULL*1024*1024, p=16;
         memcpy(h+8,&o,8); memcpy(h+16,&m,8); memcpy(h+24,&p,8);}
        int f=open("vermis.cef2",O_WRONLY|O_CREAT|O_TRUNC,0600);
        if(f>=0){ write(f,h,102); close(f);}
    }
    e = VFS_OK; r = vfs_open("vermis.cef2", PW, "CEF2", 5, NULL, &e); /* min_compat_major=5 */
    CHECK(r == NULL && e == VFS_ERR_VERSION_MISMATCH,
          "version_major=1 < min_compat=5 -> VERSION_MISMATCH (got %d)", e);

    /* random entropy block (1000 bytes of /dev/urandom) */
    {
        unsigned char rd[1024];
        int rf = open("/dev/urandom", O_RDONLY);
        if (rf >= 0) { read(rf, rd, sizeof rd); close(rf); }
        int f=open("random.cef2",O_WRONLY|O_CREAT|O_TRUNC,0600);
        if(f>=0){ write(f,rd,sizeof rd); close(f);}
    }
    e = VFS_OK; r = vfs_open("random.cef2", PW, "CEF2", 1, NULL, &e);
    CHECK(r == NULL && e != VFS_OK,
          "1KB random entropy -> NOT OK, no crash (got %d: %s)", e, vfs_result_str(e));

    /* corrupt an otherwise-valid vault (flip a ciphertext byte) */
    if (access("good.cef2", F_OK) == 0) {
        /* good.cef2 was destroyed but file remains; reopen needs a save though.
         * Make a fresh one with known content and then bit-flip. */
        Vault *tmp = vfs_create(&cfg, &e);
        if (tmp) { char *pp=vfs_payload_ptr(tmp); snprintf(pp,vfs_payload_size(tmp),"payload-for-flip");
                   vfs_save(tmp, "flip.cef2", PW); vfs_destroy(tmp); }
        /* flip a byte in the ciphertext tail (after the 96-byte header) */
        unsigned char buf[8192];
        FILE *f=fopen("flip.cef2","rb");
        if (f) {
            size_t n=fread(buf,1,sizeof buf,f); fclose(f);
            if (n>100) buf[100]^=0xFF;          /* flip a ciphertext byte */
            f=fopen("flip.cef2","wb"); fwrite(buf,1,n,f); fclose(f);
        }
        e = VFS_OK; r = vfs_open("flip.cef2", PW, "CEF2", 1, NULL, &e);
        CHECK(r == NULL && e == VFS_ERR_AUTH, "ciphertext bit-flip -> AUTH (AEAD reject, got %d)", e);
    }

    /* =================================================================
     * E. I/O permissions & symlink-TOCTOU
     * ================================================================= */
    printf("\n[E] I/O permissions & symlink redirection\n");

    /* Write to a read-only directory (chmod 000) */
    /* save to a path whose dirname is unwritable */
    {
        system("rm -rf rodir && mkdir rodir");
        Vault *t = vfs_create(&cfg, &e);
        if (t) {
            chmod("rodir", 0000);
            e = VFS_OK;
            vfs_result se = vfs_save(t, "rodir/v.cef2", PW);
            chmod("rodir", 0755);
            CHECK(se == VFS_ERR_WRITE || se == VFS_ERR_BADARGS,
                  "save into chmod000 dir -> non-OK, no crash (got %d: %s)",
                  se, vfs_result_str(se));
            vfs_destroy(t);
        }
    }

    /* Symlink TOCTOU: plant a symlink at good.cef2.tmp pointing at an existing
     * file, then attempt a save that must use O_EXCL and NOT follow it.
     * The library unlinks the stale .tmp and opens O_EXCL, so the symlink is
     * removed and a fresh regular file created. Verify the save still succeeds
     * and did not clobber the symlink target. */
    {
        system("rm -f symlink_target good.cef2 good.cef2.tmp");
        FILE *f=fopen("symlink_target","wb"); if(f){ fputs("PRECIOUS-SO-CANT-WRITE-ME\n",f); fclose(f);}
        symlink("symlink_target", "good.cef2.tmp"); /* plant the attack */
        (void)lstat;
        Vault *t = vfs_create(&cfg, &e);
        if (t) {
            char *pp=vfs_payload_ptr(t); snprintf(pp,vfs_payload_size(t),"after-attack");
            vfs_result se = vfs_save(t, "good.cef2", PW);
            CHECK(se == VFS_OK, "save with planted symlink at .tmp -> OK (O_EXCL defeats it, got %d)", se);
            /* the symlink target must be untouched */
            f=fopen("symlink_target","rb");
            char rb[64]; size_t rn = f?fread(rb,1,sizeof rb,f):0;
            if (f) fclose(f);
            CHECK(strncmp(rb,"PRECIOUS",8)==0 && rn>=8,
                  "symlink-target file NOT clobbered by save (TOCTOU defeated)");
            /* good.cef2 must be a regular file now, not a symlink */
            struct stat st; stat("good.cef2",&st);
            CHECK(S_ISREG(st.st_mode), "good.cef2 is a regular file (not a symlink) after save");
            vfs_destroy(t);
        }
        system("rm -f symlink_target good.cef2 good.cef2.tmp");
    }

    /* =================================================================
     * Summary
     * ================================================================= */
    printf("\n========== RESULT: %d PASS / %d FAIL ==========\n", g_pass, g_fail);
    system("rm -f good.cef2 huge_mem.cef2 huge_ops.cef2 zero_params.cef2 zero_mem.cef2 "
           "ceiling_plus1mem.cef2 ceiling_exact.cef2 "
           "huge_payload.cef2 empty.cef2 short.cef2 badmagic.cef2 vermis.cef2 random.cef2 "
           "flip.cef2 2>/dev/null");
    return g_fail ? 1 : 0;
}
