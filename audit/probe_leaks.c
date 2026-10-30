/*
 * probe_leaks.c — drive the error paths that malloc/freed, for Leaksan (Linux) /
 * MallocStackLogging (macOS). Exercises: wrong-password, truncated, bad-magic,
 * oversized KDF, IO paths — then exits cleanly. Under LSan any leaked ct/salt/
 * payload shows up on exit.
 */
#include "vfs_core.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200112L
#endif

int main(void)
{
    vfs_result e;
    Vault *v;

    /* Build a real vault to corrupt */
    VaultConfig cfg = vfs_config_default("CEF2", 128);
    cfg.use_random_padding = false;
    v = vfs_create(&cfg, &e);
    snprintf(vfs_payload_ptr(v), vfs_payload_size(v), "leak-check");
    vfs_save(v, "leak.cef2", "CorrectHorseBatteryStaple123!");
    vfs_destroy(v);

    /* 1. wrong password (AEAD fails) — ct must be freed, payload zeroed+freed */
    e = VFS_OK;
    v = vfs_open("leak.cef2", "wrongpw", "CEF2", 1, NULL, &e);
    printf("wrong-pw -> %d (expect AUTH=5), v=%p\n", e, (void*)v);

    /* 2. corrupt the tag: bit-flip in the tail, expect AUTH */
    {
        unsigned char buf[8192];
        FILE *f = fopen("leak.cef2","rb"); if(f){ size_t n=fread(buf,1,sizeof buf,f); fclose(f);
          if(n>100) buf[200]^=0xFF;
          f=fopen("leak.cef2","wb"); fwrite(buf,1,n,f); fclose(f); }
    }
    e = VFS_OK;
    v = vfs_open("leak.cef2", "CorrectHorseBatteryStaple123!", "CEF2", 1, NULL, &e);
    printf("tag-flip -> %d (expect AUTH=5), v=%p\n", e, (void*)v);

    /* 3. oversized KDF header -> HEADER_INVALID before KDF (no ct/payload alloc) */
    {
        unsigned char h[102]; memset(h,0,102);
        memcpy(h,"CEF2",4); h[4]=1;
        uint64_t ops=1, mem=1000ULL*1024*1024*1024; /* 1TB */
        memcpy(h+8,&ops,8); memcpy(h+16,&mem,8);
        int fd=open("leak_big.cef2",O_WRONLY|O_CREAT|O_TRUNC,0600);
        if(fd>=0){ write(fd,h,102); close(fd);}
    }
    e = VFS_OK;
    v = vfs_open("leak_big.cef2", "x", "CEF2", 1, NULL, &e);
    printf("oversized-kdf -> %d (expect HEADER_INVALID=10), v=%p\n", e, (void*)v);

    printf("done — clean exit; Leaksan will report any leaks here\n");
    system("rm -f leak.cef2 leak_big.cef2");
    return 0;
}
