# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2024 Dipl.Phys. Peer Stritzinger GmbH

AM_CPPFLAGS = -I$(top_srcdir)/tests/unity -I$(top_builddir) -I$(top_srcdir)/common \
	-I$(top_srcdir) $(CBOR_CPPFLAGS) $(ARCHIVE_CPPFLAGS)

AM_CFLAGS = $(DEBUG_CFLAGS) $(STATIC_CFLAGS)
AM_LDFLAGS = $(DEBUG_LDFLAGS) $(STATIC_LDFLAGS) $(CBOR_LDFLAGS) $(ARCHIVE_LDFLAGS)
LDADD = $(top_builddir)/common/libcommon.a $(CBOR_LIBS) $(ARCHIVE_LIBS)

check_PROGRAMS = \
	test_smoke \
	test_crypto \
	test_log \
	test_platform \
	test_footer \
	test_cbor_core \
	test_metadata_core \
	test_metadata_tree \
	test_config \
	test_azdora_config \
	test_azdora_metadata \
	test_azdora_cbor_encode \
	test_azdora_assembler \
	test_tar_gzip \
	test_piadina_metadata \
	test_piadina_context \
	test_piadina_loader \
	test_patchref

TESTS = $(check_PROGRAMS)

TESTS_ENVIRONMENT = UNITY_COMPLETE=1

test_smoke_SOURCES = test_smoke.c ../unity/unity.c
test_smoke_LDADD = $(LDADD)

test_crypto_SOURCES = test_crypto.c ../unity/unity.c
test_crypto_LDADD = $(LDADD)

test_log_SOURCES = test_log.c ../unity/unity.c
test_log_LDADD = $(LDADD)

test_platform_SOURCES = test_platform.c ../unity/unity.c
test_platform_LDADD = $(LDADD)

test_footer_SOURCES = test_footer.c ../unity/unity.c
test_footer_LDADD = $(LDADD)

test_cbor_core_SOURCES = test_cbor_core.c ../unity/unity.c
test_cbor_core_LDADD = $(LDADD)

test_metadata_core_SOURCES = test_metadata_core.c ../unity/unity.c
test_metadata_core_LDADD = $(LDADD)

test_metadata_tree_SOURCES = test_metadata_tree.c ../unity/unity.c
test_metadata_tree_LDADD = $(LDADD)

test_config_SOURCES = test_config.c ../unity/unity.c
test_config_LDADD = $(top_builddir)/piadina/piadina-config.o $(LDADD)

test_azdora_config_SOURCES = test_azdora_config.c ../unity/unity.c
test_azdora_config_LDADD = $(top_builddir)/azdora/azdora-config.o $(LDADD)

test_azdora_metadata_SOURCES = test_azdora_metadata.c ../unity/unity.c
test_azdora_metadata_LDADD = $(top_builddir)/azdora/azdora-metadata.o $(LDADD)

test_azdora_cbor_encode_SOURCES = test_azdora_cbor_encode.c ../unity/unity.c
test_azdora_cbor_encode_LDADD = $(top_builddir)/azdora/azdora-cbor_encoder.o \
	$(top_builddir)/azdora/azdora-metadata.o $(LDADD)

test_azdora_assembler_SOURCES = test_azdora_assembler.c ../unity/unity.c
test_azdora_assembler_LDADD = $(top_builddir)/azdora/azdora-assembler.o \
	$(top_builddir)/azdora/azdora-cbor_encoder.o \
	$(top_builddir)/azdora/azdora-metadata.o \
	$(top_builddir)/azdora/azdora-config.o \
	$(top_builddir)/azdora/azdora-packer_tar_gzip.o $(LDADD)

test_tar_gzip_SOURCES = test_tar_gzip.c ../unity/unity.c
test_tar_gzip_LDADD = $(top_builddir)/azdora/azdora-packer_tar_gzip.o \
	$(top_builddir)/piadina/piadina-extractor_tar_gzip.o \
	$(top_builddir)/piadina/piadina-archive.o $(LDADD)

test_piadina_metadata_SOURCES = test_piadina_metadata.c ../unity/unity.c
test_piadina_metadata_LDADD = $(top_builddir)/piadina/piadina-metadata.o $(LDADD)

test_piadina_context_SOURCES = test_piadina_context.c ../unity/unity.c
test_piadina_context_LDADD = $(top_builddir)/piadina/piadina-metadata.o \
	$(top_builddir)/piadina/piadina-context.o $(LDADD)

test_piadina_loader_SOURCES = test_piadina_loader.c ../unity/unity.c
test_piadina_loader_LDADD = $(top_builddir)/piadina/piadina-loader.o \
	$(top_builddir)/piadina/piadina-metadata.o \
	$(top_builddir)/piadina/piadina-archive.o \
	$(top_builddir)/piadina/piadina-extractor_tar_gzip.o $(LDADD)

test_patchref_SOURCES = test_patchref.c ../unity/unity.c
test_patchref_LDADD = $(top_builddir)/piadina/piadina-patchref.o $(LDADD)
