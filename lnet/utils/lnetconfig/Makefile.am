# SPDX-License-Identifier: LGPL-2.1

#
# Copyright (c) 2014, 2017, Intel Corporation.
#

#
# This file is part of Lustre, http://www.lustre.org/
#
# Author: Amir Shehata <amir.shehata@intel.com>
#

lib_LTLIBRARIES = liblnetconfig.la

liblnetconfig_la_SOURCES  = liblnetconfig.c liblnetconfig.h \
			    liblnetconfig_lnd.c liblnd.h cyaml.c cyaml.h \
			    liblnetconfig_udsp.c liblnetconfig_netlink.c
liblnetconfig_la_CPPFLAGS = -D_LARGEFILE64_SOURCE=1 -D_FILE_OFFSET_BITS=64 \
			    -DLUSTRE_UTILS=1 $(LIBNL3_CFLAGS) -fPIC
liblnetconfig_la_LDFLAGS = -L$(top_builddir)/libcfs/libcfs -lyaml -lm \
			   $(LIBREADLINE) -version-info 4:0:0
liblnetconfig_la_LIBADD = $(top_builddir)/libcfs/libcfs/libcfs.la \
			  $(LIBNL3_LIBS)

EXTRA_DIST =
