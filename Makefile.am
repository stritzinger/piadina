# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2024 Dipl.Phys. Peer Stritzinger GmbH

ACLOCAL_AMFLAGS = -I m4

SUBDIRS = common piadina azdora tests

EXTRA_DIST = \
	autogen.sh

if HAVE_DOXYGEN
doc: Doxyfile
	$(MKDIR_P) doc/api
	$(DOXYGEN) Doxyfile

clean-local:
	rm -rf doc
else
doc:
	@echo "doxygen not found, cannot generate documentation"
endif

.PHONY: doc
