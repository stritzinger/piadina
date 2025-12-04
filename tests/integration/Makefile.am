TESTS = test_bins.sh test_static_link.sh

if STATIC_BUILD
TESTS_ENVIRONMENT = TOP_BUILDDIR='@top_builddir@' STATIC_BUILD=yes
else
TESTS_ENVIRONMENT = TOP_BUILDDIR='@top_builddir@' STATIC_BUILD=no
endif

EXTRA_DIST = test_bins.sh test_static_link.sh
