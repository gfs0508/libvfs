#include "vfs_core.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

static double now_ms(void){ struct timespec t; clock_gettime(CLOCK_MONOTONIC,&t); return t.tv_sec*1000.0+t.tv_nsec/1e6; }

int main(int argc, char **argv)
{
    unsigned long long ops = argc > 1 ? strtoull(argv[1],0,10) : 3;
    unsigned long long mem = argc > 2 ? strtoull(argv[2],0,10) : (64ULL*1024*1024);
    vfs_result e = VFS_OK;
    double t = now_ms();
    if (vfs_check_runtime_environment() != VFS_OK) { printf("RT FAIL\n"); fflush(stdout); return 2; }
    printf("init: %.1f ms  (ops=%llu mem=%llu=%lLuMiB)\n", now_ms()-t, ops, mem, mem/(1024*1024));
    fflush(stdout);

    VaultConfig cfg = vfs_config_default("CEF2", 64);
    cfg.ops_limit = ops;
    cfg.mem_limit = mem;
    cfg.use_random_padding = false;
    Vault *v = vfs_create(&cfg, &e);
    if (!v) { printf("create FAILED e=%d\n", e); return 3; }
    char *p = vfs_payload_ptr(v);
    snprintf(p, vfs_payload_size(v), "bench");

    double t0 = now_ms();
    e = vfs_save(v, "bench.cef2", "pw");
    double dt = now_ms() - t0;
    printf("save: %.1f ms (e=%d)\n", dt, e);
    fflush(stdout);

    double t1 = now_ms();
    Vault *r = vfs_open("bench.cef2", "pw", "CEF2", 1, NULL, &e);
    double dt2 = now_ms() - t1;
    printf("open: %.1f ms (e=%d) %s\n", dt2, e, r ? "OK" : "NULL");
    vfs_destroy(r);
    vfs_destroy(v);
    printf("done\n");
    return 0;
}
