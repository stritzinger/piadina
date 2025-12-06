# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2024 Dipl.Phys. Peer Stritzinger GmbH

bin_PROGRAMS = piadina
piadina_SOURCES = main.c config.c config.h extractor_tar_gzip.c extractor_tar_gzip.h archive.c archive.h metadata.c metadata.h context.c context.h loader.c loader.h
piadina_CPPFLAGS = -I$(top_builddir) -I$(top_srcdir) $(CBOR_CPPFLAGS) $(ARCHIVE_CPPFLAGS)
piadina_CFLAGS = $(DEBUG_CFLAGS) $(STATIC_CFLAGS)
piadina_LDFLAGS = $(DEBUG_LDFLAGS) $(STATIC_LDFLAGS) $(CBOR_LDFLAGS) $(ARCHIVE_LDFLAGS)
piadina_LDADD = $(top_builddir)/common/libcommon.a $(CBOR_LIBS) $(ARCHIVE_LIBS)
