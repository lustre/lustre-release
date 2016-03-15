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

lib_LTLIBRARIES = liblnetconfig.la

CYAML := $(top_builddir)/lnet/utils/cyaml/cyaml.c \
	 $(top_builddir)/lnet/utils/cyaml/cyaml.h
liblnetconfig_la_SOURCES  = liblnetconfig.c liblnetconfig.h \
			    liblnetconfig_lnd.c liblnd.h $(CYAML)
liblnetconfig_la_CPPFLAGS = -D_LARGEFILE64_SOURCE=1 -D_FILE_OFFSET_BITS=64 \
			    -DLUSTRE_UTILS=1 -I$(top_builddir)/lnet/utils/cyaml
liblnetconfig_la_LDFLAGS = -L$(top_builddir)/libcfs/libcfs -version-info 1:1:0

EXTRA_DIST =
