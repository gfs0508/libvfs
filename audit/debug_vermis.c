#include "vfs_core.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

int main(void)
{
    vfs_check_runtime_environment();
    unsigned char h[120];
    memset(h, 0, sizeof h);
    memcpy(h, "CEF2", 4);
    h[4] = 1; h[5] = 0;                 /* version_major=1, minor=0 */
    uint64_t ops = 3, mem = 64ULL*1024*1024, psz = 16;
    memcpy(h + 8,  &ops, 8);
    memcpy(h + 16, &mem, 8);
    memcpy(h + 24, &psz, 8);
    /* Append a 16-byte body so the file is 80 bytes total (still < 96-byte header) */
    for (int i = 0; i < 16; i++) h[96 + i] = (unsigned char)(i + 1);

    int f = open("vermis_dbg.cef2", O_WRONLY|O_CREAT|O_TRUNC, 0600);
    if (f < 0) { perror("open"); return 1; }
    ssize_t w = write(f, h, 96);       /* write only the 96-byte header */
    printf("wrote %zd bytes\n", w);
    close(f);
    struct stat st; stat("vermis_dbg.cef2", &st);
    printf("on-disk file size = %lld bytes\n", (long long)st.st_size);

    /* First: inspect what the header reader thinks */
    VaultHeaderInfo info;
    vfs_result ie = vfs_inspect_file("vermis_dbg.cef2", &info);
    printf("inspect -> %d (%s), version_major=%u, payload_size=%zu\n",
           ie, vfs_result_str(ie), info.version_major, info.payload_size);

    vfs_result e = VFS_OK;
    Vault *v = vfs_open("vermis_dbg.cef2", "PW", "CEF2", 5, NULL, &e);
    printf("vfs_open(min_compat_major=5) -> v=%p err=%d (%s)\n",
           (void*)v, e, vfs_result_str(e));
    vfs_destroy(v);
    remove("vermis_dbg.cef2");
    return 0;
}
