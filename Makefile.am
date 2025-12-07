ACLOCAL_AMFLAGS = -I m4

SUBDIRS = server tests

# Distribution of additional files
EXTRA_DIST = \
			 README.md \
			 .clang-format \
			 .clang-tidy \
			 .env \
			 .gitignore \
			 docs/structure.md \
			 docs/development.md \
			 scripts/install_nasfsctl.sh \
			 scripts/generate_compile_commands.sh \
			 utils/nasfsctl \
			 scripts/setup_deps.sh

# Install control script
bin_SCRIPTS = utils/nasfsctl

# Create required directories during installation
install-data-local:
	$(MKDIR_P) $(DESTDIR)$(localstatedir)/run/nasfs
	$(MKDIR_P) $(DESTDIR)$(localstatedir)/log/nasfs
	chmod 755 $(DESTDIR)$(localstatedir)/run/nasfs
	chmod 755 $(DESTDIR)$(localstatedir)/log/nasfs

# Installation check that ensures scripts are copied to build directory
installcheck-local:
	@echo "Running installcheck for main project..."
