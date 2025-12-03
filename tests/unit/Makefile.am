AM_CPPFLAGS = -I$(top_srcdir)/tests/unity -I$(top_builddir)

check_PROGRAMS = test_smoke
TESTS = $(check_PROGRAMS)

TESTS_ENVIRONMENT = UNITY_COMPLETE=1

test_smoke_SOURCES = test_smoke.c ../unity/unity.c
