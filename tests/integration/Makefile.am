# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2024 Dipl.Phys. Peer Stritzinger GmbH

TESTS = test_bins.sh test_static_link.sh test_pack_extract.sh test_cache_payload_overrides.sh

if STATIC_BUILD
TESTS_ENVIRONMENT = TOP_BUILDDIR='@top_builddir@' STATIC_BUILD=yes
else
TESTS_ENVIRONMENT = TOP_BUILDDIR='@top_builddir@' STATIC_BUILD=no
endif

EXTRA_DIST = test_bins.sh test_static_link.sh test_pack_extract.sh test_cache_payload_overrides.sh
