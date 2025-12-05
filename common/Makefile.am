# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2024 Dipl.Phys. Peer Stritzinger GmbH

# Common library built for internal use.
noinst_LIBRARIES = libcommon.a

AM_CPPFLAGS = $(CBOR_CPPFLAGS) $(ARCHIVE_CPPFLAGS)
AM_CFLAGS = $(DEBUG_CFLAGS) $(STATIC_CFLAGS)

libcommon_a_SOURCES = \
	log.c \
	log.h \
	platform.c \
	platform.h \
	footer.c \
	footer.h \
	cbor_core.c \
	cbor_core.h \
	metadata_core.c \
	metadata_core.h \
	crypto.c \
	crypto.h
