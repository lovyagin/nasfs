#!/bin/sh
# autoclean.sh

echo "Removing autotools generated files..."

rm -rf autom4te.cache/ m4
rm -f aclocal.m4
rm -f configure
rm -f config.h.in config.h.in~
rm -f Makefile.in */Makefile.in
rm -f compile config.guess config.sub
rm -f install-sh missing
rm -f depcomp test-driver

rm -f config.log config.status
rm -f Makefile */Makefile
rm -f stamp-h1
rm -rf *build*/*

echo "Cleanup completed."
