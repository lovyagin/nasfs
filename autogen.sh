#!/bin/sh
# autogen.sh - Bootstrap the GNU Autotools system for NASFS

set -e

echo "Initializing autotools build system for NASFS..."

# Create m4 directory for macros if it doesn't exist
if [ ! -d "m4" ]; then
    mkdir m4
    echo "Created m4 directory for macros"
fi

# Check for required programs
for prog in aclocal autoconf autoheader automake; do
    if ! command -v $prog >/dev/null 2>&1; then
        echo "Error: could not find required program: $prog"
        echo "Please install GNU Autotools"
        exit 1
    fi
done

echo "Running aclocal..."
aclocal -I m4

echo "Running autoconf..."
autoconf

echo "Running autoheader..."
autoheader

echo "Running automake..."
automake --add-missing --copy

echo "Autotools initialization completed successfully."
echo ""
echo "You can now run:"
echo "mkdir build"
echo "cd build"
echo "  ../configure"
echo "  make"
echo "  make install"
echo ""
echo "For more configuration options, run: ./configure --help"
