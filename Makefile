# ============================================================================
#  Makefile — Universal Build System for libvfs
#  Target    : POSIX Compliant / Multi-platform (macOS, Linux, Windows)
#  Patch     : FIX #7 — the previous Makefile omitted the libsodium include
#              path, so `make` failed with "sodium.h: No such file or
#              directory". This version auto-detects libsodium via pkg-config
#              with Homebrew/Linux/MSYS2 fallbacks, and builds examples.
# ============================================================================

LIB_NAME = libvfs.a
SRC      = vfs_core.c
OBJ      = $(SRC:.c=.o)

# ----------------------------------------------------------------------------
# Base C99 compilation flags. -Werror promotes any warning to an error, so a
# clean build requires zero diagnostics under -Wall -Wextra -Wpedantic.
# ----------------------------------------------------------------------------
CFLAGS = -O3 -std=c99 -Wall -Wextra -Wpedantic -Werror -D_POSIX_C_SOURCE=200112L
LDFLAGS = -lsodium

# ----------------------------------------------------------------------------
# FIX #7: automatic libsodium include/library path detection.
#
#  1. pkg-config --cflags / --libs is the canonical source of truth and
#     works on Linux and Homebrew/Linuxbrew macOS.
#  2. If pkg-config reports nothing (or libsodium isn't on the
#     default linker search path), fall back to well-known locations:
#        Apple Silicon  : /opt/homebrew
#        Intel macOS    : /usr/local
#        Debian/Ubuntu  : system /usr/include and /usr/lib (the include path
#                        is implicit so the fallback is a no-op, but the
#                        LDFLAGS stay as-is via -lsodium).
#  3. The user can override at any time:  make CFLAGS=... LDFLAGS=...
# ----------------------------------------------------------------------------
PKGCONF_CFLAGS := $(shell pkg-config --cflags libsodium 2>/dev/null)
PKGCONF_LIBS   := $(shell pkg-config --libs   libsodium 2>/dev/null)

UNAME_S := $(shell uname -s 2>/dev/null || echo Unknown)
UNAME_M := $(shell uname -m 2>/dev/null || echo x86_64)

ifeq ($(UNAME_S),Darwin)
    # Homebrew locations on macOS.  Apple Silicon first, then Intel.
    ifneq ($(PKGCONF_CFLAGS),)
        SODIUM_CFLAGS = $(PKGCONF_CFLAGS)
        SODIUM_LIBS   = $(PKGCONF_LIBS)
    else ifeq ($(UNAME_M),arm64)
        SODIUM_CFLAGS = -I/opt/homebrew/include
        # Link-time: Homebrew keeps libs in a keg that isn't on the default
        # search path; add its lib dir via LDFLAGS so -lsodium resolves.
        SODIUM_LIBS   = -L/opt/homebrew/lib -lsodium
    else
        SODIUM_CFLAGS = -I/usr/local/include
        SODIUM_LIBS   = -L/usr/local/lib -lsodium
    endif
else
    # Linux / MSYS2 / MinGW: rely on pkg-config, fall back to -lsodium.
    ifneq ($(PKGCONF_CFLAGS),)
        SODIUM_CFLAGS = $(PKGCONF_CFLAGS)
        SODIUM_LIBS   = $(PKGCONF_LIBS)
    else
        SODIUM_CFLAGS =
        SODIUM_LIBS   = -lsodium
    endif
endif

# Fold the detected include/path flags into CFLAGS; use SODIUM_LIBS exclusively
# (it already carries -lsodium when pkg-config is used, so LDFLAGS stays empty
# to avoid a duplicate-library link warning on ld).
CFLAGS   += $(SODIUM_CFLAGS)
LDFLAGS  := $(SODIUM_LIBS)

# ----------------------------------------------------------------------------
# Platform-Specific Optimisation Parameters
# ----------------------------------------------------------------------------
ifeq ($(UNAME_S),Darwin)
    CC = clang
    ifeq ($(UNAME_M),arm64)
         CFLAGS += -arch arm64 -mcpu=native
    endif

else ifeq ($(UNAME_S),Linux)
    CC = gcc
         # Enables host-native instruction set extensions (AVX2, AVX-512, or NEON)
    CFLAGS += -march=native -fPIC

else ifneq (,$(findstring MINGW,$(UNAME_S)))
    CC = gcc
    CFLAGS += -march=native
    LIB_NAME = vfs.lib
endif

# ----------------------------------------------------------------------------
# Build Rules and Targets
# ----------------------------------------------------------------------------
.PHONY: all clean examples

all: $(LIB_NAME)

$(LIB_NAME): $(OBJ)
	@echo "Constructing static library $(LIB_NAME) for $(UNAME_S) ($(UNAME_M))..."
	ar rcs $@ $^

%.o: %.c
	@echo "CC  $<"; $(CC) $(CFLAGS) -c $< -o $@

# ----------------------------------------------------------------------------
# Build the example programs from fixed_libvfs/ (or CWD). Linking them
# confirms the library plus its public header are self-consistent.
# ----------------------------------------------------------------------------
examples: $(LIB_NAME)
	@echo "CC  example_simple.c"; $(CC) $(CFLAGS) -I. $(LDFLAGS) example_simple.c $(LIB_NAME) -o example_simple
	@echo "CC  example_advanced.c"; $(CC) $(CFLAGS) -I. $(LDFLAGS) example_advanced.c $(LIB_NAME) -o example_advanced

clean:
	rm -f $(OBJ) $(LIB_NAME) *.tmp example_simple example_advanced
