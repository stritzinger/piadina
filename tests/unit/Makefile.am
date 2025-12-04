AM_CPPFLAGS = -I$(top_srcdir)/tests/unity -I$(top_builddir) -I$(top_srcdir)/common \
	$(CBOR_CPPFLAGS) $(ARCHIVE_CPPFLAGS)

AM_CFLAGS = $(DEBUG_CFLAGS) $(STATIC_CFLAGS)
AM_LDFLAGS = $(DEBUG_LDFLAGS) $(STATIC_LDFLAGS) $(CBOR_LDFLAGS) $(ARCHIVE_LDFLAGS)
LDADD = $(top_builddir)/common/libcommon.a $(CBOR_LIBS) $(ARCHIVE_LIBS)

check_PROGRAMS = \
	test_smoke \
	test_log \
	test_platform \
	test_footer \
	test_cbor_core \
	test_metadata_core

TESTS = $(check_PROGRAMS)

TESTS_ENVIRONMENT = UNITY_COMPLETE=1

test_smoke_SOURCES = test_smoke.c ../unity/unity.c
test_smoke_LDADD = $(LDADD)

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
