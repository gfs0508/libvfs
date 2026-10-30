/*
 * test_basic.c - Happy-path smoke test for libvfs (CEF2)
 * Builds a vault, encrypts a payload, saves, reopens, verifies, destroys.
 * C99. Build:  clang -std=c99 -Wall -Wextra -I libvfs *.c -lsodium
 */
#include "vfs_core.h"
#include <stdio.h>
#include <string.h>

#define PW "MasterPassphrase123!"

int main(void)
{
    vfs_result err = VFS_ERR_IO;
    VaultConfig cfg;
    Vault *v = NULL;
    char *p;
    const char *path = "basic.cef2";
    int fails = 0;

    if (vfs_check_runtime_environment() != VFS_OK) {
        printf("[FAIL] runtime env: %s\n", vfs_result_str(VFS_ERR_LIB_VERSION));
        return 1;
    }
    printf("[ ok ] runtime environment OK\n");

    cfg = vfs_config_default("CEF2", 256);
    v = vfs_create(&cfg, &err);
    if (!v || err != VFS_OK) {
        printf("[FAIL] vfs_create: %s\n", vfs_result_str(err));
        return 1;
    }
    printf("[ ok ] vfs_create (256 B, default KDF 3/64MiB)\n");

    p = vfs_payload_ptr(v);
    snprintf(p, vfs_payload_size(v), "hello libvfs: secret payload %02x%02x", 0xde, 0xad);
    printf("[ ok ] payload_ptr=%p size=%zu\n", (void *)p, vfs_payload_size(v));

    err = vfs_save(v, path, PW);
    if (err != VFS_OK) {
        printf("[FAIL] vfs_save: %s\n", vfs_result_str(err));
        vfs_destroy(v);
        return 1;
    }
    printf("[ ok ] vfs_save -> %s\n", path);

    vfs_destroy(v);
    printf("[ ok ] vfs_destroy (zeroised + freed)\n");

    /* Reopen */
    VaultHeaderInfo info;
    err = VFS_ERR_BADARGS;
    v = vfs_open(path, PW, "CEF2", 1, &info, &err);
    if (!v || err != VFS_OK) {
        printf("[FAIL] vfs_open (reopen): %s\n", vfs_result_str(err));
        return 1;
    }
    printf("[ ok ] vfs_open (reopen): payload_size=%zu ops=%llu mem=%zu\n",
           info.payload_size, (unsigned long long)info.ops_limit, info.mem_limit);

    p = vfs_payload_ptr(v);
    if (strncmp(p, "hello libvfs: secret payload dead", 33) == 0)
        printf("[ ok ] round-trip payload intact\n");
    else {
        printf("[FAIL] round-trip payload mismatch: '%s'\n", p);
        fails++;
    }

    /* Wrong password must be rejected cleanly */
    err = VFS_OK;
    Vault *bad = vfs_open(path, "wrong-password", "CEF2", 1, NULL, &err);
    if (bad != NULL || err != VFS_ERR_AUTH) {
        printf("[FAIL] wrong-password not rejected (v=%p err=%d)\n", (void *)bad, err);
        fails++;
        if (bad) vfs_destroy(bad);
    } else {
        printf("[ ok ] wrong-password rejected: %s\n", vfs_result_str(VFS_ERR_AUTH));
    }

    vfs_destroy(v);
    printf("[ ok ] final vfs_destroy\n");

    printf("\n==== TEST_BASIC: %s ====\n", fails ? "FAILURES" : "ALL PASS");
    return fails ? 1 : 0;
}
