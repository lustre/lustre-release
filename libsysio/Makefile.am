AUTOMAKE_OPTIONS=1.6

if WITH_TESTS
TESTDIR = tests
else
TESTDIR =
endif

include $(top_srcdir)/src/module.mk 
include $(top_srcdir)/include/module.mk
include $(top_srcdir)/tests/module.mk
include $(top_srcdir)/dev/stdfd/module.mk 
include $(top_srcdir)/drivers/incore/module.mk 
include $(top_srcdir)/drivers/native/module.mk 
include $(top_srcdir)/drivers/yod/module.mk
include $(top_srcdir)/drivers/sockets/module.mk

lib_LIBRARIES = ${LIBBUILD_DIR}/libsysio.a

if WITH_STDFD_DEV
OPTIONAL_STDFD_SRCS = $(STDFD_SRCS)
else
OPTIONAL_STDFD_SRCS =
endif

if WITH_INCORE_DRIVER
OPTIONAL_INCORE_SRCS = $(INCORE_SRCS)
else
OPTIONAL_INCORE_SRCS =
endif

if WITH_NATIVE_DRIVER
OPTIONAL_NATIVE_SRCS = $(NATIVE_SRCS)
else
OPTIONAL_NATIVE_SRCS =
endif

if WITH_SOCKETS_DRIVER
OPTIONAL_SOCKETS_SRCS = $(SOCKETS_SRCS)
else
OPTIONAL_SOCKETS_SRCS =
endif

if WITH_CPLANT_YOD
OPTIONAL_YOD_SRCS = $(YOD_SRCS)
else
OPTIONAL_YOD_SRCS =
endif

if WITH_LUSTRE_HACK
# it would be better that let configure script check this
OPTIONAL_LUSTRE_CFLAGS = -fPIC
endif

AM_CFLAGS = $(OPTIONAL_LUSTRE_CFLAGS)

__LIBBUILD_DIR__libsysio_a_SOURCES = \
	$(SRCDIR_SRCS) \
	$(OPTIONAL_STDFD_SRCS) \
	$(OPTIONAL_INCORE_SRCS) \
	$(OPTIONAL_SOCKETS_SRCS) \
	$(OPTIONAL_NATIVE_SRCS) \
	$(OPTIONAL_YOD_SRCS)

include $(top_srcdir)/Rules.make

EXTRA_DIST = Rules.make misc/init-env.sh $(TESTS_EXTRA) $(SRCDIR_EXTRA) \
	$(INCLUDE_EXTRA) $(STDFD_EXTRA) $(INCORE_EXTRA) \
	$(SOCKETS_EXTRA) $(NATIVE_EXTRA) $(YOD_EXTRA)

AM_CPPFLAGS += ${YOD_DRIVER_FLAGS}

really-clean: testsclean maintainer-clean
	-rm -rf autom4te-2.53.cache
	-rm -rf .deps
	-rm -f Makefile.in 
	-rm -f compile depcomp INSTALL install-sh missing mkinstalldirs \
		configure aclocal.m4 
	-rm -f config.guess config.sub
	-rm -rf $(LIBBUILD_DIR)
	-rm -f libsysio*.tar.gz
	cd $(TESTDIR); rm -rf Makefile Makefile.in .deps

tests: $(lib_LIBRARIES) FORCE
	cd $(TESTDIR); make
testsclean: FORCE
	cd $(TESTDIR); make clean
clean: testsclean clean-am
FORCE:
