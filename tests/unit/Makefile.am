AM_CPPFLAGS = -I$(top_srcdir)/tests/unity -I$(top_builddir) -I$(top_srcdir)/common

LDADD = $(top_builddir)/common/libcommon.a

check_PROGRAMS = \
	test_smoke \
	test_log \
	test_platform \
	test_footer

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
