#!/usr/bin/env bash

# autoclean.sh -- Deep clean script for NASFS project
# Removes generated files from a source-tree build.

set -euo pipefail

echo "Starting aggressive project cleanup..."

# Use the generated makefiles for source-tree build products.
if [[ -f Makefile && -x config.status ]]; then
    "${MAKE:-make}" distclean
fi

# Leave separate build trees, runtime directories and local m4 macros intact.
rm -rf autom4te.cache/
rm -f aclocal.m4 configure config.h.in config.h.in~ stamp-h1
rm -f ar-lib compile config.guess config.sub depcomp install-sh ltmain.sh missing test-driver
rm -f Makefile.in common/Makefile.in server/Makefile.in client/Makefile.in tests/Makefile.in

echo "Project is clean."
