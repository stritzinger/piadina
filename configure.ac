AC_PREREQ([2.69])
AC_INIT([Piadina Project],[0.1.0],[support@stritzinger.com])
AC_CONFIG_SRCDIR([piadina/main.c])
AC_CONFIG_HEADERS([piadina_config.h])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([foreign subdir-objects color-tests])
AM_SILENT_RULES([yes])

AC_PROG_CC
AC_PROG_RANLIB

AC_CHECK_HEADER([cbor.h], [], [AC_MSG_ERROR([libcbor headers not found])])
AC_SEARCH_LIBS([cbor_load], [cbor], [], [AC_MSG_ERROR([libcbor library not found])])

AC_DEFINE([PACKAGE_COPYRIGHT], [Copyright 2024, Dipl.Phys. Peer Stritzinger GmbH <peer@stritzinger.org>.], [Package copyright])

AC_CONFIG_FILES([
Makefile
common/Makefile
piadina/Makefile
azdora/Makefile
tests/Makefile
tests/unity/Makefile
tests/unit/Makefile
tests/integration/Makefile
])
AC_OUTPUT
