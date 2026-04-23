# autoclean.sh -- Deep clean script for NASFS project
# Removes all build artifacts, generated files, and temporary data.

echo "Starting aggressive project cleanup..."

# 1. Remove Autotools generated files
echo "Cleaning Autotools..."
rm -rf autom4te.cache/ m4/
rm -f aclocal.m4 configure config.h.in config.h.in~ stamp-h1
rm -f ar-lib compile config.guess config.sub depcomp install-sh ltmain.sh missing test-driver

# Remove generated Makefiles and dependencies recursively
find . -name "Makefile.in" -type f -delete
find . -name "Makefile" -type f -delete
find . -name ".deps" -type d -exec rm -rf {} +
find . -name ".libs" -type d -exec rm -rf {} +
find . -name "*.o" -type f -delete
find . -name "*.lo" -type f -delete
find . -name "*.la" -type f -delete
find . -name "*.a" -type f -delete
find . -name "*.dirstamp" -type f -delete

# 2. Remove CMake artifacts
echo "Cleaning CMake..."
rm -rf CMakeFiles/ CMakeCache.txt cmake_install.cmake install_manifest.txt CTestTestfile.cmake
rm -rf _CPack_Packages/ CPackConfig.cmake CPackSourceConfig.cmake
rm -rf build*/ out/ bin/

# 3. Remove runtime data and logs
echo "Cleaning logs and storage..."
rm -f nasfs.log nasfs.pid
rm -rf storage/
rm -f config.log config.status config.h

# 4. Remove test artifacts
echo "Cleaning test workspace..."
rm -rf tests/workspace/
find tests/ -name "*.log" -type f -delete
find tests/ -name "*.trs" -type f -delete

# 5. Remove misc temporary files
echo "Cleaning temporary files..."
find . -name "*.tmp" -type f -delete
find . -name "*.bak" -type f -delete
find . -name "*~" -type f -delete
find . -name ".DS_Store" -type f -delete

echo "Project is clean."
