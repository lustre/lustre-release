#
# LGPL HEADER START
#
# DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as
# published by the Free Software Foundation; either version 2.1 of the
# License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library. If not, see <http://www.gnu.org/licenses/>.
#
# LGPL HEADER END

#
# Copyright (c) 2014, Intel Corporation.
#

# Author:
#   Amir Shehata <amir.shehata@intel.com>
#

SUBDIRS =

AM_CFLAGS=$(LLCFLAGS)
AM_CPPFLAGS=$(LLCPPFLAGS) -I$(top_builddir)/lnet/utils \
			  -I$(top_builddir)/lnet/utils/cyaml \
			  -DLUSTRE_UTILS=1
AM_LDFLAGS := -L$(top_builddir)/libcfs/libcfs

lib_LIBRARIES = liblnetconfig.a
noinst_LIBRARIES = liblnetconfigtmp.a

CYAML := $(top_builddir)/lnet/utils/cyaml/cyaml.c \
	 $(top_builddir)/lnet/utils/cyaml/cyaml.h
liblnetconfigtmp_a_SOURCES := liblnetconfig.c liblnetconfig.h $(CYAML)
liblnetconfigtmp_a_CPPFLAGS := $(AM_CPPFLAGS)

# build static and share lib lnet config library
liblnetconfig.a : liblnetconfigtmp.a
	rm -f liblnetconfig.a liblnetconfig.so
	$(CC) $(LDFLAGS) $(AM_LDFLAGS) -shared -o liblnetconfig.so `$(AR) -t liblnetconfigtmp.a`
	mv liblnetconfigtmp.a liblnetconfig.a

install-exec-hook:
	cp liblnetconfig.so  $(DESTDIR)$(libdir)/

EXTRA_DIST =
