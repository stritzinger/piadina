# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2024 Dipl.Phys. Peer Stritzinger GmbH

bin_PROGRAMS = azdora
azdora_SOURCES = \
	main.c \
	config.c \
	metadata.c \
	cbor_encoder.c \
	assembler.c \
	packer_tar_gzip.c \
	packer_tar_gzip.h

azdora_CPPFLAGS = -I$(top_builddir) -I$(top_srcdir) -I$(top_srcdir)/common $(CBOR_CPPFLAGS) $(ARCHIVE_CPPFLAGS)
azdora_CFLAGS = $(DEBUG_CFLAGS) $(STATIC_CFLAGS)
azdora_LDFLAGS = $(DEBUG_LDFLAGS) $(STATIC_LDFLAGS) $(CBOR_LDFLAGS) $(ARCHIVE_LDFLAGS)
azdora_LDADD = $(top_builddir)/common/libcommon.a $(CBOR_LIBS) $(ARCHIVE_LIBS)
