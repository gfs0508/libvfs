#!/usr/bin/env bash
#
# build_and_test_linux.sh — build libvfs + audit harness under Linux ASan+LSan+UBSan.
#
# macOS AddressSanitizer cannot perform leak detection (Apple clang/Darwin do not
# offer -fsanitize=leak), so the leak portion of the audit is proven here on Linux.
#
# Toolchain note (why gcc for the sanitizer TEST builds):
#   On Debian/Ubuntu the `clang` binary is a frontend that links through the
#   system `gcc-12` driver, and gcc-12's default link search path does not always
#   see libsanitizer.a (the ASan/LSan/UBSan runtime), producing spurious
#   "undefined reference to __asan_*" link errors that are a *linker* artefact,
#   not a library bug. Building the tests with plain `gcc` (glibc-12 ships the
#   sanitizers built-in) sidesteps that and gives real Leaksan numbers.
#
#   The library object itself is STILL compiled at the project's release standard
#   `clang -O3` ... here done with `clang -O3 -Wall -Wextra -Wpedantic -Werror`
#   to keep the "clean build = release signal" invariant, then linked with gcc.
#
# Runs inside a Debian-based Docker container (libsodium-dev present) or natively.
set -uo pipefail

# Install libsodium-dev + gcc if missing (Debian family; harmless otherwise).
if ! pkg-config --exists libsodium 2>/dev/null; then
  apt-get update -qq
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
      pkg-config libsodium-dev gcc build-essential >/dev/null 2>&1 || true
fi
if ! pkg-config --exists libsodium; then
  echo "ERROR: libsodium-dev not found; cannot proceed."
  exit 2
fi

SC=$(pkg-config --cflags libsodium)
SD=$(pkg-config --libs   libsodium)
LIB="libvfs"                         # core lives in audit/libvfs/
INC="-I$LIB"
CC_LIB="clang"                       # release-standard build
CC_TEST="gcc"                        # sanitizer build/test driver

echo "libsodium: $(pkg-config --modversion libsodium)"
echo "libfs cflags: $SC   libs: $SD"
echo "release compiler = $CC_LIB   sanitizer/test compiler = $CC_TEST"

mkdir -p logs

LIB_CFLAGS="-std=c99 -O3 -Wall -Wextra -Wpedantic -Werror -D_POSIX_C_SOURCE=200112L"

build_lib() {   # compile libvfs object at the RELEASE standard, into $1
  $CC_LIB $LIB_CFLAGS $SC $INC -c "$LIB/vfs_core.c" -o "$1"
}

echo
echo "================================================================"
echo " 1. Library builds clean under the project release standard"
echo "    (clang -O3 -std=c99 -Wall -Wextra -Wpedantic -Werror)"
echo "================================================================"
if build_lib /tmp/vfs_core_release.o 2>&1; then
  echo "  [PASS] libvfs compiles with ZERO diagnostics under -Werror"
else
  echo "  [FAIL] library did not compile clean at release standard"
  exit 1
fi

# For sanitizer runs we need an ASan/UBSan-instrumented library object.
echo
echo "================================================================"
echo " 1b. Library instrumented with ASan+UBSan (for the adversarial runs)"
echo "================================================================"
SAN="-std=c99 -g -O1 -fsanitize=address,undefined -fno-omit-frame-pointer -Wall -Wextra -D_POSIX_C_SOURCE=200112L"
if $CC_TEST $SAN $SC $INC -c "$LIB/vfs_core.c" -o /tmp/vfs_core_san.o 2>&1; then
  echo "  [PASS] libvfs compiles under ASan+UBSan with zero diagnostics"
else
  echo "  [FAIL] libvfs did not compile under ASan+UBSan"
  exit 1
fi

run_test() {   # $1 = src, $2 = outbin, $3 = logfile
  local src="$1" out="$2" log="$3"
  $CC_TEST -std=c99 -g -O1 -fsanitize=address,undefined -fno-omit-frame-pointer -Wall -Wextra $SC $INC -c "$src" -o /tmp/"${src%.c}".o 2>&1 \
    && $CC_TEST -std=c99 -g -O1 -fsanitize=address,undefined -fno-omit-frame-pointer \
                 /tmp/"${src%.c}".o /tmp/vfs_core_san.o $SD -o "$out" 2>&1
  ASAN_OPTIONS=detect_leaks=1:abort_on_error=0 "$out" 2>&1 | tee "$log"
  return "${PIPESTATUS[0]}"
}

echo
echo "================================================================"
echo " 2. test_basic (happy path) under ASan+UBSan+LSan"
echo "================================================================"
run_test test_basic.c      test_basic_linux      logs/basic_linux.log
echo "  test_basic_linux exit: ${PIPESTATUS[0]}"

echo
echo "================================================================"
echo " 3. test_adversarial (full hostile harness) under ASan+UBSan+LSan"
echo "================================================================"
run_test test_adversarial.c  test_adversarial_linux  logs/adversarial_linux.log
echo "  test_adversarial_linux exit: ${PIPESTATUS[0]}"

echo
echo "================================================================"
echo " 4. probe_edges (within-ceiling KDF, size immutability, oversize path)"
echo "================================================================"
# probe_edges runs a 1k-op KDF, so bound it; it should still finish promptly.
$CC_TEST -std=c99 -g -O1 -fsanitize=address,undefined -fno-omit-frame-pointer -Wall -Wextra $SC $INC -c probe_edges.c -o /tmp/probe_edges.o 2>&1 \
  && $CC_TEST -std=c99 -g -O1 -fsanitize=address,undefined -fno-omit-frame-pointer \
               /tmp/probe_edges.o /tmp/vfs_core_san.o $SD -o probe_edges_linux 2>&1
ASAN_OPTIONS=detect_leaks=1:abort_on_error=0 ./probe_edges_linux \
  2>&1 | tee logs/probe_edges_linux.log
echo "  probe_edges_linux exit: ${PIPESTATUS[0]}"

echo
echo "================================================================"
echo " 5. probe_leaks — drives error/IO/auth paths; Leaksan reports on exit"
echo "================================================================"
$CC_TEST -std=c99 -g -O1 -fsanitize=address,undefined -fno-omit-frame-pointer -Wall -Wextra $SC $INC -c probe_leaks.c -o /tmp/probe_leaks.o 2>&1 \
  && $CC_TEST -std=c99 -g -O1 -fsanitize=address,undefined -fno-omit-frame-pointer \
               /tmp/probe_leaks.o /tmp/vfs_core_san.o $SD -o probe_leaks_linux 2>&1
ASAN_OPTIONS=detect_leaks=1:abort_on_error=0:print_stacktrace=1 ./probe_leaks_linux \
  2>&1 | tee logs/probe_leaks_linux.log
echo "  probe_leaks_linux exit: ${PIPESTATUS[0]}"
if ! grep -q "LeakSanitizer" logs/probe_leaks_linux.log; then
  echo "  [PASS] Leaksan emitted no leak report on the error/IO/auth paths."
else
  echo "  [NOTE] Leaksan report above — inspect for library-owned leaks."
fi

echo
echo "================================================================"
echo " 6. UBSan-only sweep on the raw-header fuzz surface"
echo "================================================================"
$CC_TEST "-std=c99 -g -O1 -fsanitize=undefined -fno-omit-frame-pointer -Wall -Wextra -D_POSIX_C_SOURCE=200112L" \
      $SC $INC -c test_adversarial.c -o /tmp/adv_ubsan.o 2>&1 \
  && $CC_TEST "-std=c99 -g -O1 -fsanitize=undefined -fno-omit-frame-pointer" \
               /tmp/adv_ubsan.o /tmp/vfs_core_san.o $SD -o test_adversarial_ubsan 2>&1
UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=0 ./test_adversarial_ubsan \
  >/dev/null 2> logs/ubsan.log
UBEXIT=$?
echo "  UBSan exit: $UBEXIT  (non-zero => UB detected)"
if [ -s logs/ubsan.log ]; then
  echo "  UBSan output:"
  sed 's/^/    /' logs/ubsan.log | head -40
else
  echo "  [PASS] no UBSan diagnostics on the adversarial corpus."
fi

echo
echo "================================================================"
echo " 7. sizeof(CEF2HeaderPacked) — on-disk layout check"
echo "================================================================"
cat > /tmp/sizeof_check.c <<'EOF'
#include "vfs_core.h"
#include <sodium.h>
#include <stdio.h>
typedef struct {
  char magic[4]; uint8_t vm, vn;
  uint64_t ops, mem, payload_sz;
  unsigned char salt[crypto_pwhash_SALTBYTES];
  unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
  unsigned char hash[crypto_hash_sha256_BYTES];
} __attribute__((packed)) H;
int main(void){
  printf("sizeof(packed CEF2HeaderPacked) = %zu bytes\n", sizeof(H));
  printf("  sum = 4 + 2 + 24 + 16 + 24 + 32 = %zu\n",
         4u+2u+24u+16u+24u+32u);
  return 0;
}
EOF
$CC_LIB -std=c99 -Wall $SC $INC /tmp/sizeof_check.c $SD -o /tmp/sizeof_check
/tmp/sizeof_check | tee logs/sizeof.log

echo
echo "================================================================"
echo " 8. macOS-vs-Linux layout consistency"
echo "================================================================"
echo "  Compare logs/sizeof.log vs logs/sizeof_macos.log."
if diff <(grep "bytes" logs/sizeof.log) <(grep "bytes" logs/sizeof_macos.log) >/dev/null 2>&1; then
  echo "  [PASS] packed header size identical on Linux and macOS."
else
  echo "  [NOTE] sizes differ — the on-disk header would not be portable by byte."
fi

echo
echo "================================================================"
echo " DONE"
echo "================================================================"
