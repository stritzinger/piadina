<!--
SPDX-FileCopyrightText: 2024 Dipl.Phys. Peer Stritzinger GmbH
SPDX-License-Identifier: Apache-2.0
-->

<a name="piadina--azdora"></a>
## Piadina / Azdora

This repository contains the **Piadina** launcher and the **Azdora** packer.
Both executables are built through the same Autotools project.

## Table of Contents

- [Piadina / Azdora](#piadina--azdora)
- [Build Instructions](#build-instructions)
  - [Prerequisites](#prerequisites)
  - [Static vs Dynamic Builds](#static-vs-dynamic-builds)
  - [Bootstrap, Configure, Build](#bootstrap-configure-build)
  - [Build Troubleshooting](#build-troubleshooting)
  - [Cleaning Up](#cleaning-up)
- [Quickstart: build a sample self-extracting binary](#quickstart-build-a-sample-self-extracting-binary)
- [Interpreter patching with PATCHELF_SET_INTERPRETER](#interpreter-patching-with-patchelf_set_interpreter)

<a name="build-instructions"></a>
## Build Instructions

<a name="prerequisites"></a>
### Prerequisites

- POSIX shell (`/bin/sh`)
- GNU Autotools toolchain:
  - `autoconf` ≥ 2.69
  - `automake` ≥ 1.16
  - `libtool` (pulled in automatically on most systems)
- Standard C compiler toolchain (e.g. `gcc`, `clang`)

#### Required Packages

On Debian/Ubuntu, install the following:

```sh
sudo apt update
sudo apt install autoconf automake libtool build-essential \
    libcbor-dev libarchive-dev
```

#### Optional Packages (for Portable Static Builds)

For maximum portability, you can use musl libc instead of glibc. When musl
tooling is installed, `configure` will automatically detect and use it for
static builds:

```sh
sudo apt install musl-dev musl-tools
```

<a name="static-vs-dynamic-builds"></a>
### Static vs Dynamic Builds

By default, `configure` attempts to produce **fully static binaries** that are
self-contained and do not depend on system shared libraries. This makes the
binaries portable across different Linux systems.

#### Static Build Behavior

When `--disable-static-build` is **not** specified (the default):

1. `configure` checks if `musl-gcc` is available
2. If found, it automatically uses musl for maximum portability
3. It looks for static libraries in local directories first, then system paths
4. If any static library is missing, `configure` fails with helpful guidance

#### Static Build Requirements

For static builds, you need static versions of the following libraries:

- **libc** (static): Usually `libc6-dev` on glibc systems, or `musl-dev` for
  musl-based builds (recommended).
- **libcbor** (static): The static library `libcbor.a` is required.
- **libarchive** (static): The static library `libarchive.a` is required.

#### Building Libraries Locally (Recommended)

Many Linux distributions only ship shared libraries (`.so`) for libcbor and
libarchive. Instead of installing static versions system-wide, you can build
them locally inside the project directory. The `configure` script will
automatically detect and use them.

> **⚠️ Important: musl auto-detection**
>
> If `musl-gcc` is installed on your system, it will be **used by default** for
> static builds (for maximum portability). This means the libraries below
> **must be built with `CC=musl-gcc`** or the build will fail.
>
> To check if musl is installed: `which musl-gcc`
>
> To explicitly disable musl and use glibc: `./configure --without-musl`

**Building libcbor locally:**

```sh
# From the piadina project root
git clone https://github.com/PJK/libcbor.git
cd libcbor

# If musl-gcc is installed (recommended for portable binaries):
# Note: CMAKE_C_COMPILER_AR/RANLIB must be set as musl-gcc doesn't provide them
CC=musl-gcc cmake -B _build \
    -DCMAKE_C_COMPILER_AR=/usr/bin/ar \
    -DCMAKE_C_COMPILER_RANLIB=/usr/bin/ranlib \
    -DBUILD_SHARED_LIBS=OFF \
    -DWITH_TESTS=OFF

# Or without musl (use --without-musl when configuring piadina):
# cmake -B _build -DBUILD_SHARED_LIBS=OFF -DWITH_TESTS=OFF

cmake --build _build -j$(nproc)
cd ..
```

**Building libarchive locally:**

Note: libarchive has a `build/` directory in its source tree, so we use `_build` instead.

```sh
# From the piadina project root
git clone https://github.com/libarchive/libarchive.git
cd libarchive

# If musl-gcc is installed (recommended for portable binaries):
# Note: CMAKE_C_COMPILER_AR/RANLIB must be set as musl-gcc doesn't provide them
CC=musl-gcc cmake -B _build \
    -DCMAKE_C_COMPILER_AR=/usr/bin/ar \
    -DCMAKE_C_COMPILER_RANLIB=/usr/bin/ranlib \
    -DENABLE_TEST=OFF \
    -DENABLE_OPENSSL=OFF \
    -DENABLE_ZLIB=OFF \
    -DENABLE_BZip2=OFF \
    -DENABLE_LZMA=OFF \
    -DENABLE_ZSTD=OFF \
    -DENABLE_LZ4=OFF \
    -DENABLE_EXPAT=OFF \
    -DENABLE_ICONV=OFF \
    -DPOSIX_REGEX_LIB=NONE \
    -DENABLE_LIBB2=OFF \
    -DENABLE_LIBXML2=OFF

# Or without musl (use --without-musl when configuring piadina):
# cmake -B _build \
#     -DENABLE_TEST=OFF \
#     -DENABLE_OPENSSL=OFF \
#     -DENABLE_ZLIB=OFF \
#     -DENABLE_BZip2=OFF \
#     -DENABLE_LZMA=OFF \
#     -DENABLE_ZSTD=OFF \
#     -DENABLE_LZ4=OFF \
#     -DENABLE_EXPAT=OFF \
#     -DENABLE_ICONV=OFF \
#     -DPOSIX_REGEX_LIB=NONE \
#     -DENABLE_LIBB2=OFF \
#     -DENABLE_LIBXML2=OFF

cmake --build _build -j$(nproc)
cd ..
```

After building both libraries, `configure` will automatically find them:

```sh
./configure
# Output will show:
#   Local libcbor:      yes
#   Local libarchive:   yes
```

The local library directories are expected to have one of these layouts:

- **Build tree layout** (after `cmake --build build`):
  - `libcbor/src/cbor.h` + `libcbor/build/src/libcbor.a`
  - `libarchive/libarchive/archive.h` + `libarchive/build/libarchive/libarchive.a`

- **Install layout** (after `cmake --install` with `--prefix`):
  - `libcbor/include/cbor.h` + `libcbor/lib/libcbor.a`
  - `libarchive/include/archive.h` + `libarchive/lib/libarchive.a`

#### Installing Libraries System-Wide (Alternative)

If you prefer to install the static libraries system-wide using command:

```sh
sudo cmake --install build
```

#### Dynamic Builds

If static libraries are not available, you can fall back to dynamic linking:

```sh
./configure --disable-static-build
make
```

This produces binaries that depend on system shared libraries at runtime.

<a name="bootstrap-configure-build"></a>
### Bootstrap, Configure, Build

From the repository root:

1. **Bootstrap Autotools files**

   ```sh
   ./autogen.sh
   ```

   This runs `autoreconf --install --force`, generating `configure` and the
   various `Makefile.in` files.

2. **Configure the project**

   ```sh
   ./configure
   ```

   Common options:

   - `--disable-static-build`: Build dynamically linked binaries
   - `--with-musl`: Force use of musl-gcc (error if not found)
   - `--without-musl`: Do not use musl-gcc even if available
   - `--enable-debug`: Enable extra debug logging and symbols
   - `--prefix=PATH`: Set installation prefix
   - `CC=compiler`: Override C compiler (e.g., `CC=clang`)
   - `CFLAGS=flags`: Pass custom compiler flags

   **Note**: When musl-gcc is detected and static builds are enabled, it is
   used automatically. Use `--without-musl` to build with glibc instead.

3. **Build**

   ```sh
   make
   ```

   The resulting binaries live in `piadina/piadina` and `azdora/azdora`.

4. **Run the test suite (optional but recommended)**

   ```sh
   make check
   ```

   This executes the Unity-based unit tests and integration tests. For static
   builds, it also verifies that the binaries are indeed statically linked.

5. **Verify static linkage (optional)**

   ```sh
   ldd piadina/piadina
   ```

   For a statically linked binary, this should report "not a dynamic executable".

6. **Install (optional)**

   ```sh
   make install
   ```

   Use `DESTDIR` or `--prefix` to control the installation target.

<a name="build-troubleshooting"></a>
### Build Troubleshooting

#### "libcbor headers not found"

Install the development package or build locally:

```sh
# Option 1: Install system package (for dynamic builds)
sudo apt install libcbor-dev

# Option 2: Build locally (for static builds)
git clone https://github.com/PJK/libcbor.git
cd libcbor && cmake -B build -DBUILD_SHARED_LIBS=OFF -DWITH_TESTS=OFF && cmake --build build
```

For musl/static details, see the earlier sections on local libcbor builds (musl
notes and static flags).

#### "libarchive headers not found"

Install the development package or build locally:

```sh
# Option 1: Install system package (for dynamic builds)
sudo apt install libarchive-dev

# Option 2: Build locally (for static builds)
git clone https://github.com/libarchive/libarchive.git
cd libarchive && cmake -B build -DENABLE_OPENSSL=OFF -DENABLE_TEST=OFF && cmake --build build -j$(nproc)
```

For musl/static details, see the earlier sections on local libarchive builds
(musl notes and static flags).

#### "static libcbor library is not available"

This error means configure found the libcbor headers but not the static library
(`libcbor.a`). Solutions:

1. Build libcbor locally in the `libcbor/` directory (see above)
2. Install a static version system-wide
3. Use `--disable-static-build` for a dynamic build

#### "static libarchive library is not available"

This error means configure found the libarchive headers but not the static
library (`libarchive.a`). Solutions:

1. Build libarchive locally in the `libarchive/` directory (see above)
2. Install a static version system-wide
3. Use `--disable-static-build` for a dynamic build

#### "static libc is not available"

This typically means the static C library is not installed. On Debian/Ubuntu:

```sh
sudo apt install libc6-dev
```

For musl-based builds (recommended), install `musl-dev`.

#### "musl-gcc not found" (when using --with-musl)

Install the musl tools:

```sh
sudo apt install musl-dev musl-tools
```

<a name="cleaning-up"></a>
### Cleaning Up

- `make clean` removes build artifacts from the source tree.
- `make distclean` additionally removes files generated by `configure`.
- `git clean -xfd` resets the tree completely (use with care; this deletes
  untracked files).

<a name="quickstart-build-a-sample-self-extracting-binary"></a>
## Quickstart: build a sample self-extracting binary

A minimal sample payload lives in `samples/simple`. It prints its
arguments, can dump selected environment variables, and can exit with a chosen
code.

Build a self-extracting binary using the in-tree launcher and sample payload:

```sh
PIADINA_BIN=./piadina/piadina
AZDORA_BIN=./azdora/azdora
PAYLOAD_DIR=./samples/simple
OUTPUT=/tmp/piadina-sample.bin

"$AZDORA_BIN" \
  --launcher "$PIADINA_BIN" \
  --payload "$PAYLOAD_DIR" \
  --output "$OUTPUT" \
  --meta APP_NAME="Piadina Simple Example" \
  --meta APP_VER="1.0.0" \
  --meta ENTRY_POINT=entry.sh \
  --meta ENTRY_ARGS[]="--print-env" \
  --meta ENV.CUSTOM_FOO="foo" \
  --meta ENV.CUSTOM_BAR="bar"
```

Run it (pass any extra args; `--exit N` sets the exit code):

```sh
"$OUTPUT" --launcher-log-level=info -- "hello" "arg with space" --exit 7
```

<a name="interpreter-patching-with-patchelf_set_interpreter"></a>
## Interpreter patching with `PATCHELF_SET_INTERPRETER`

Piadina can patch ELF interpreters after extraction, before the payload is marked ready. This is useful when you embed your own dynamic loader (e.g., musl or a relocated glibc loader) and need every dynamic binary in the payload to use it.

How to use:

- Add metadata entries: `PATCHELF_SET_INTERPRETER[]=<target>:<interpreter>`.
  - `target`: relative path inside the payload archive (no templating).
  - `interpreter`: path to set; supports templates (e.g., `{PAYLOAD_ROOT}/lib/ld-musl-x86_64.so.1`).
- With Azdora CLI: `--meta PATCHELF_SET_INTERPRETER[]=bin/app:{PAYLOAD_ROOT}/lib/ld-musl-x86_64.so.1`
- Multiple entries are allowed; each target is patched independently and idempotently (skipped if already set).

Behavior and constraints:

- Runs during extraction in `TEMP_DIR` before rename to `PAYLOAD_ROOT`.
- Works on ET_EXEC/ET_DYN ELF only; fails clearly on non-ELF or static binaries.
- If the new interpreter is longer than the existing `.interp`, Piadina relocates/grows the interpreter string; it fails only when the ELF layout cannot be safely rewritten or on I/O errors.
- Supports 32-bit and 64-bit ELF on Linux.

To inspect results in tests, use `readelf -l` to check “Requesting program interpreter” and run the patched binaries.
