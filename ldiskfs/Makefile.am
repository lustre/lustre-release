AUTOMAKE_OPTIONS = foreign
SUBDIRS = ldiskfs
EXTRA_DIST = @PACKAGE_TARNAME@.spec
EXTRA_DIST += kernel_patches
EXTRA_DIST += config

dist-hook:
	find $(distdir) -name .deps -o \
			-name .git -o \
			-name .#* | xargs rm -rf
	$(MAKE) $(AM_MAKEFLAGS) \
	  top_distdir="$(top_distdir)" distdir="$(distdir)" \
	  module-dist-hook

rpms: @PACKAGE_TARNAME@.spec dist Makefile
	CONFIGURE_ARGS=$$(echo $$(eval echo $(ac_configure_args)) | \
		sed -re 's/--(en|dis)able-tests//'); \
	if [ -n "@LINUX@" ]; then \
		CONFIGURE_ARGS=$$(echo $$(eval echo $$CONFIGURE_ARGS) | \
			sed -re 's/--with-linux=[^ ][^ ]*//'); \
		RPMARGS="--define \"kdir @LINUX@\""; \
		CONFIGURE_ARGS=$$(echo $$(eval echo $$CONFIGURE_ARGS) | \
			sed -re 's/--with-linux-obj=[^ ][^ ]*//'); \
		if [ -n "@LINUX_OBJ@" -a "@LINUX_OBJ@" != "@LINUX@" ]; then \
			RPMARGS="$$RPMARGS --define \"kobjdir @LINUX_OBJ@\""; \
		fi; \
	fi; \
	CONFIGURE_ARGS=$$(echo $$(eval echo $$CONFIGURE_ARGS) | \
		sed -re 's/--with-release=[^ ][^ ]*//'); \
	RPMARGS="$$RPMARGS --define \"configure_args $$CONFIGURE_ARGS\""; \
	echo "Building ldiskfs RPM with $$RPMARGS"; \
	eval rpmbuild $$RPMARGS -ta $(distdir).tar.gz

srpm: @PACKAGE_TARNAME@.spec dist Makefile
	eval rpmbuild $$RPMARGS -ta $(distdir).tar.gz

# this only needs to be done if disting stand-alone (i.e. not as a
# subdir of lustre
module-dist-hook:
	if ! grep "AC_INIT(\[Lustre\], \[LUSTRE_VERSION\], \[http:\/\/bugs\.whamcloud\.com\/], \[lustre\])" ../configure.ac; then \
	    if [ -f META ]; then \
		cp META $(distdir)/META; \
	    fi; \
	fi
