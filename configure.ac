# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2024 Dipl.Phys. Peer Stritzinger GmbH

AC_PREREQ([2.69])
AC_INIT([Piadina Project],[0.1.0],[support@stritzinger.com])
AC_CONFIG_SRCDIR([piadina/main.c])
AC_CONFIG_HEADERS([piadina_config.h])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([foreign subdir-objects color-tests])
AM_SILENT_RULES([yes])

dnl ============================================================
dnl Debug build support (disabled by default for release builds)
dnl ============================================================

AC_ARG_ENABLE([debug],
    [AS_HELP_STRING([--enable-debug],
        [build with debug symbols and no optimization @<:@default=release@:>@])],
    [enable_debug="$enableval"],
    [enable_debug=no])

dnl ============================================================
dnl Static build support (enabled by default)
dnl ============================================================

AC_ARG_ENABLE([static-build],
    [AS_HELP_STRING([--disable-static-build],
        [build dynamically linked binaries instead of fully static @<:@default=static@:>@])],
    [enable_static_build="$enableval"],
    [enable_static_build=yes])

AM_CONDITIONAL([STATIC_BUILD], [test "x$enable_static_build" = "xyes"])

dnl ============================================================
dnl Musl toolchain detection and configuration
dnl ============================================================

AC_ARG_WITH([musl],
    [AS_HELP_STRING([--with-musl],
        [use musl-gcc for static builds (auto-detected by default)])
AS_HELP_STRING([--without-musl],
        [do not use musl-gcc even if available])],
    [with_musl="$withval"],
    [with_musl=auto])

dnl Check if musl-gcc is available
AC_MSG_CHECKING([for musl-gcc])
AS_IF([test "x$with_musl" != "xno"], [
    AC_PATH_PROG([MUSL_GCC], [musl-gcc], [no])
    AS_IF([test "x$MUSL_GCC" != "xno"], [
        AC_MSG_RESULT([$MUSL_GCC])
        have_musl=yes
    ], [
        AC_MSG_RESULT([no])
        have_musl=no
    ])
], [
    AC_MSG_RESULT([disabled by user])
    have_musl=no
])

dnl Decide whether to use musl
use_musl=no
AS_IF([test "x$enable_static_build" = "xyes"], [
    AS_IF([test "x$with_musl" = "xyes"], [
        dnl User explicitly requested musl
        AS_IF([test "x$have_musl" = "xyes"], [
            use_musl=yes
        ], [
            AC_MSG_ERROR([--with-musl specified but musl-gcc not found. Install musl-tools.])
        ])
    ], [test "x$with_musl" = "xauto"], [
        dnl Auto-detect: use musl if available for static builds
        AS_IF([test "x$have_musl" = "xyes"], [
            use_musl=yes
            AC_MSG_NOTICE([musl-gcc found, using it for static build])
        ])
    ])
])

dnl Set the compiler based on musl detection
AS_IF([test "x$use_musl" = "xyes"], [
    CC="$MUSL_GCC"
    AC_MSG_NOTICE([Using musl-gcc as C compiler: $CC])
])

AC_PROG_CC
AC_PROG_RANLIB

dnl ============================================================
dnl Set compiler flags based on debug/release mode
dnl ============================================================

dnl Override default CFLAGS set by AC_PROG_CC (usually "-g -O2")
AS_IF([test "x$enable_debug" = "xyes"], [
    dnl Debug build: include debug symbols, minimal optimization
    DEBUG_CFLAGS="-g -O0"
    DEBUG_LDFLAGS=""
    AC_MSG_NOTICE([Debug build enabled])
], [
    dnl Release build: no debug symbols, full optimization, strip binaries
    DEBUG_CFLAGS="-O2 -DNDEBUG"
    DEBUG_LDFLAGS="-Wl,--strip-all"
    AC_MSG_NOTICE([Release build (use --enable-debug for debug symbols)])
])
AC_SUBST([DEBUG_CFLAGS])
AC_SUBST([DEBUG_LDFLAGS])

dnl ============================================================
dnl Local library directories (for developer builds)
dnl ============================================================

dnl Get absolute path to source directory for local library paths
dnl This is needed because builds happen in subdirectories
case "$srcdir" in
    /*)
        abs_srcdir="$srcdir"
        ;;
    *)
        abs_srcdir="$(cd "$srcdir" && pwd)"
        ;;
esac

dnl Check for locally built libcbor
LIBCBOR_LOCAL_DIR="$abs_srcdir/libcbor"
LIBCBOR_CPPFLAGS=""
LIBCBOR_LDFLAGS=""
use_local_libcbor=no
LIBCBOR_BUILD_DIR=""

AC_MSG_CHECKING([for local libcbor build])
dnl Check _build first, then build
if test -f "$LIBCBOR_LOCAL_DIR/src/cbor.h" && test -f "$LIBCBOR_LOCAL_DIR/_build/src/libcbor.a"; then
    AC_MSG_RESULT([yes (in libcbor/_build/)])
    use_local_libcbor=yes
    LIBCBOR_BUILD_DIR="$LIBCBOR_LOCAL_DIR/_build"
    dnl Include paths: src/ for main headers, _build/ for generated configuration.h, _build/src/cbor/ for export header
    LIBCBOR_CPPFLAGS="-I$LIBCBOR_LOCAL_DIR/src -I$LIBCBOR_BUILD_DIR -I$LIBCBOR_BUILD_DIR/src"
    LIBCBOR_LDFLAGS="-L$LIBCBOR_BUILD_DIR/src"
elif test -f "$LIBCBOR_LOCAL_DIR/src/cbor.h" && test -f "$LIBCBOR_LOCAL_DIR/build/src/libcbor.a"; then
    AC_MSG_RESULT([yes (in libcbor/build/)])
    use_local_libcbor=yes
    LIBCBOR_BUILD_DIR="$LIBCBOR_LOCAL_DIR/build"
    dnl Include paths: src/ for main headers, build/ for generated configuration.h, build/src/cbor/ for export header
    LIBCBOR_CPPFLAGS="-I$LIBCBOR_LOCAL_DIR/src -I$LIBCBOR_BUILD_DIR -I$LIBCBOR_BUILD_DIR/src"
    LIBCBOR_LDFLAGS="-L$LIBCBOR_BUILD_DIR/src"
elif test -f "$LIBCBOR_LOCAL_DIR/include/cbor.h" && test -f "$LIBCBOR_LOCAL_DIR/lib/libcbor.a"; then
    dnl Alternative layout (installed into libcbor/include and libcbor/lib)
    AC_MSG_RESULT([yes (in libcbor/ with include/lib layout)])
    use_local_libcbor=yes
    LIBCBOR_CPPFLAGS="-I$LIBCBOR_LOCAL_DIR/include"
    LIBCBOR_LDFLAGS="-L$LIBCBOR_LOCAL_DIR/lib"
else
    AC_MSG_RESULT([no])
fi

dnl Check for locally built libarchive
LIBARCHIVE_LOCAL_DIR="$abs_srcdir/libarchive"
LIBARCHIVE_CPPFLAGS=""
LIBARCHIVE_LDFLAGS=""
use_local_libarchive=no
LIBARCHIVE_BUILD_DIR=""

AC_MSG_CHECKING([for local libarchive build])
dnl Check _build first (recommended to avoid conflict with libarchive's build/ source dir)
if test -f "$LIBARCHIVE_LOCAL_DIR/libarchive/archive.h" && test -f "$LIBARCHIVE_LOCAL_DIR/_build/libarchive/libarchive.a"; then
    AC_MSG_RESULT([yes (in libarchive/_build/)])
    use_local_libarchive=yes
    LIBARCHIVE_BUILD_DIR="$LIBARCHIVE_LOCAL_DIR/_build"
    LIBARCHIVE_CPPFLAGS="-I$LIBARCHIVE_LOCAL_DIR/libarchive -I$LIBARCHIVE_BUILD_DIR"
    LIBARCHIVE_LDFLAGS="-L$LIBARCHIVE_BUILD_DIR/libarchive"
elif test -f "$LIBARCHIVE_LOCAL_DIR/libarchive/archive.h" && test -f "$LIBARCHIVE_LOCAL_DIR/build/libarchive/libarchive.a"; then
    AC_MSG_RESULT([yes (in libarchive/build/)])
    use_local_libarchive=yes
    LIBARCHIVE_BUILD_DIR="$LIBARCHIVE_LOCAL_DIR/build"
    LIBARCHIVE_CPPFLAGS="-I$LIBARCHIVE_LOCAL_DIR/libarchive -I$LIBARCHIVE_BUILD_DIR"
    LIBARCHIVE_LDFLAGS="-L$LIBARCHIVE_BUILD_DIR/libarchive"
elif test -f "$LIBARCHIVE_LOCAL_DIR/include/archive.h" && test -f "$LIBARCHIVE_LOCAL_DIR/lib/libarchive.a"; then
    dnl Alternative layout (installed into libarchive/include and libarchive/lib)
    AC_MSG_RESULT([yes (in libarchive/ with include/lib layout)])
    use_local_libarchive=yes
    LIBARCHIVE_CPPFLAGS="-I$LIBARCHIVE_LOCAL_DIR/include"
    LIBARCHIVE_LDFLAGS="-L$LIBARCHIVE_LOCAL_DIR/lib"
else
    AC_MSG_RESULT([no])
fi

dnl Add local library paths to CPPFLAGS and LDFLAGS for subsequent checks
saved_CPPFLAGS="$CPPFLAGS"
saved_LDFLAGS="$LDFLAGS"

AS_IF([test "x$use_local_libcbor" = "xyes"], [
    CPPFLAGS="$LIBCBOR_CPPFLAGS $CPPFLAGS"
    LDFLAGS="$LIBCBOR_LDFLAGS $LDFLAGS"
])

AS_IF([test "x$use_local_libarchive" = "xyes"], [
    CPPFLAGS="$LIBARCHIVE_CPPFLAGS $CPPFLAGS"
    LDFLAGS="$LIBARCHIVE_LDFLAGS $LDFLAGS"
])

dnl ============================================================
dnl Check local library compiler compatibility (musl vs glibc)
dnl ============================================================

dnl If using musl, check that local libraries don't contain glibc-specific symbols
AS_IF([test "x$use_musl" = "xyes"], [
    dnl Check local libcbor for glibc symbols
    AS_IF([test "x$use_local_libcbor" = "xyes"], [
        AC_MSG_CHECKING([if local libcbor is musl-compatible])
        AS_IF([nm "$LIBCBOR_BUILD_DIR/src/libcbor.a" 2>/dev/null | grep -q -E 'gnu_dev_'], [
            AC_MSG_RESULT([no (built with glibc)])
            AC_MSG_ERROR([
Local libcbor was built with glibc but musl is being used.
Rebuild libcbor with CC=musl-gcc. See README.md for instructions.])
        ], [
            AC_MSG_RESULT([yes])
        ])
    ])
    dnl Check local libarchive for glibc symbols
    AS_IF([test "x$use_local_libarchive" = "xyes"], [
        AC_MSG_CHECKING([if local libarchive is musl-compatible])
        AS_IF([nm "$LIBARCHIVE_BUILD_DIR/libarchive/libarchive.a" 2>/dev/null | grep -q -E 'gnu_dev_'], [
            AC_MSG_RESULT([no (built with glibc)])
            AC_MSG_ERROR([
Local libarchive was built with glibc but musl is being used.
Rebuild libarchive with CC=musl-gcc. See README.md for instructions.])
        ], [
            AC_MSG_RESULT([yes])
        ])
    ])
])

dnl ============================================================
dnl Check for required libraries
dnl ============================================================

dnl Check for libcbor headers
AC_CHECK_HEADER([cbor.h], [],
    [AC_MSG_ERROR([libcbor headers not found. Install libcbor-dev or build locally in libcbor/.])])

dnl Check for libarchive headers (needed for future milestones)
AC_CHECK_HEADER([archive.h], [],
    [AC_MSG_ERROR([libarchive headers not found. Install libarchive-dev or build locally in libarchive/.])])

dnl For static builds, we need to verify static library availability
AS_IF([test "x$enable_static_build" = "xyes"], [
    dnl Save current flags
    check_saved_LDFLAGS="$LDFLAGS"
    check_saved_LIBS="$LIBS"

    dnl Check for static libc support
    AC_MSG_CHECKING([for static linking support])
    LDFLAGS="$LDFLAGS -static"
    AC_LINK_IFELSE(
        [AC_LANG_PROGRAM([[#include <stdio.h>]], [[printf("test");]])],
        [
            AC_MSG_RESULT([yes])
            static_libc_ok=yes
        ],
        [
            AC_MSG_RESULT([no])
            static_libc_ok=no
        ])
    LDFLAGS="$check_saved_LDFLAGS"

    AS_IF([test "x$static_libc_ok" != "xyes"], [
        AC_MSG_ERROR([
Static build requested but static libc is not available.
On Debian/Ubuntu, you may need to install libc6-dev or use musl-dev.
Alternatively, use --disable-static-build for dynamic linking.
        ])
    ])

    dnl Check for static libcbor
    AC_MSG_CHECKING([for static libcbor])

    check_saved_LDFLAGS="$LDFLAGS"
    check_saved_LIBS="$LIBS"
    LDFLAGS="$LDFLAGS -static"
    LIBS="-lcbor $LIBS"

    AC_LINK_IFELSE(
        [AC_LANG_PROGRAM([[
            #include <cbor.h>
        ]], [[
            cbor_item_t *item = cbor_new_definite_map(1);
            cbor_decref(&item);
        ]])],
        [static_libcbor_ok=yes],
        [static_libcbor_ok=no])

    LIBS="$check_saved_LIBS"
    LDFLAGS="$check_saved_LDFLAGS"

    AS_IF([test "x$static_libcbor_ok" = "xyes"], [
        AS_IF([test "x$use_local_libcbor" = "xyes"], [
            AC_MSG_RESULT([yes (local build)])
        ], [
            AC_MSG_RESULT([yes (system)])
        ])
    ], [
        AC_MSG_RESULT([no])
        AC_MSG_ERROR([
Static libcbor not found. See README.md for build instructions.
Note: If musl is installed, it is used by default. Libraries must be built with CC=musl-gcc.
Use --without-musl to build with glibc, or --disable-static-build for dynamic linking.])
    ])

    dnl Check for static libarchive
    AC_MSG_CHECKING([for static libarchive])

    check_saved_LDFLAGS="$LDFLAGS"
    check_saved_LIBS="$LIBS"
    LDFLAGS="$LDFLAGS -static"
    static_libarchive_ok=no

    dnl Try linking with -larchive statically - try multiple dependency combinations
    dnl Start with minimal deps and add more if needed
    for archive_libs in \
        "-larchive" \
        "-larchive -lz" \
        "-larchive -lz -llzma -lbz2 -lzstd -llz4 -lexpat" \
        "-larchive -lz -llzma -lbz2" \
    ; do
        LIBS="$archive_libs $check_saved_LIBS"
        AC_LINK_IFELSE(
            [AC_LANG_PROGRAM([[
                #include <archive.h>
            ]], [[
                struct archive *a = archive_read_new();
                archive_read_free(a);
            ]])],
            [
                static_libarchive_ok=yes
                ARCHIVE_STATIC_LIBS="$archive_libs"
                break
            ],
            [])
    done

    LIBS="$check_saved_LIBS"
    LDFLAGS="$check_saved_LDFLAGS"

    AS_IF([test "x$static_libarchive_ok" = "xyes"], [
        AS_IF([test "x$use_local_libarchive" = "xyes"], [
            AC_MSG_RESULT([yes (local build)])
        ], [
            AC_MSG_RESULT([yes (system)])
        ])
    ], [
        AC_MSG_RESULT([no])
        AC_MSG_ERROR([
Static libarchive not found. See README.md for build instructions.
Note: If musl is installed, it is used by default. Libraries must be built with CC=musl-gcc.
Use --without-musl to build with glibc, or --disable-static-build for dynamic linking.])
    ])

    dnl Set static linking flags with dead code elimination
    dnl -ffunction-sections -fdata-sections: Put each function/data in its own section
    dnl -Wl,--gc-sections: Let linker garbage collect unused sections
    dnl This significantly reduces binary size when linking large static libraries
    dnl Note: stripping is handled by DEBUG_LDFLAGS based on --enable-debug
    STATIC_CFLAGS="-ffunction-sections -fdata-sections"
    STATIC_LDFLAGS="-static -Wl,--gc-sections"
    AC_SUBST([STATIC_CFLAGS])
    AC_SUBST([STATIC_LDFLAGS])

], [
    dnl Dynamic build - just check libraries are available
    AC_SEARCH_LIBS([cbor_load], [cbor], [],
        [AC_MSG_ERROR([libcbor library not found])])
    AC_SEARCH_LIBS([archive_read_new], [archive], [],
        [AC_MSG_ERROR([libarchive library not found])])
    STATIC_CFLAGS=""
    STATIC_LDFLAGS=""
    AC_SUBST([STATIC_CFLAGS])
    AC_SUBST([STATIC_LDFLAGS])
])

dnl ============================================================
dnl Export library flags for Makefiles
dnl ============================================================

dnl Combine local and system flags
CBOR_CPPFLAGS="$LIBCBOR_CPPFLAGS"
CBOR_LDFLAGS="$LIBCBOR_LDFLAGS"
CBOR_LIBS="-lcbor"
AC_SUBST([CBOR_CPPFLAGS])
AC_SUBST([CBOR_LDFLAGS])
AC_SUBST([CBOR_LIBS])

ARCHIVE_CPPFLAGS="$LIBARCHIVE_CPPFLAGS"
ARCHIVE_LDFLAGS="$LIBARCHIVE_LDFLAGS"
dnl Use detected static libs for static builds, otherwise just -larchive
AS_IF([test -n "$ARCHIVE_STATIC_LIBS"], [
    ARCHIVE_LIBS="$ARCHIVE_STATIC_LIBS"
], [
    ARCHIVE_LIBS="-larchive"
])
AC_SUBST([ARCHIVE_CPPFLAGS])
AC_SUBST([ARCHIVE_LDFLAGS])
AC_SUBST([ARCHIVE_LIBS])

dnl ============================================================
dnl Documentation support (Doxygen)
dnl ============================================================

AC_CHECK_PROGS([DOXYGEN], [doxygen])
if test -z "$DOXYGEN"; then
    AC_MSG_WARN([doxygen not found - documentation generation will not be available])
fi
AM_CONDITIONAL([HAVE_DOXYGEN], [test -n "$DOXYGEN"])

dnl ============================================================
dnl Package metadata
dnl ============================================================

AC_DEFINE([PACKAGE_COPYRIGHT],
    [Copyright 2024, Dipl.Phys. Peer Stritzinger GmbH <peer@stritzinger.org>.],
    [Package copyright])

dnl ============================================================
dnl Output summary
dnl ============================================================

AS_IF([test "x$enable_debug" = "xyes"], [build_type="debug"], [build_type="release"])

AC_MSG_NOTICE([
Piadina Project configuration summary:
  Build type:         $build_type
  Static build:       $enable_static_build
  Using musl:         $use_musl
  C compiler:         $CC
  Local libcbor:      $use_local_libcbor
  Local libarchive:   $use_local_libarchive
])

AC_CONFIG_FILES([
Makefile
Doxyfile
common/Makefile
piadina/Makefile
azdora/Makefile
tests/Makefile
tests/unity/Makefile
tests/unit/Makefile
tests/integration/Makefile
])
AC_OUTPUT
