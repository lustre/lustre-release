#
# GPL HEADER START
#
# DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 only,
# as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License version 2 for more details (a copy is included
# in the LICENSE file that accompanied this code).
#
# You should have received a copy of the GNU General Public License
# version 2 along with this program; If not, see
# http://www.sun.com/software/products/lustre/docs/GPLv2.pdf
#
# Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
# CA 95054 USA or visit www.sun.com if you need additional information or
# have any questions.
#
# GPL HEADER END
#

#
# Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
# Use is subject to license terms.
#

#
# This file is part of Lustre, http://www.lustre.org/
# Lustre is a trademark of Sun Microsystems, Inc.
#

AM_CFLAGS = $(LLCFLAGS)

if BUILD_DLC
SUBDIRS = lnetconfig
endif

AM_LDFLAGS := -L$(top_builddir)/lnet/utils/lnetconfig

LIBCFS= $(top_builddir)/libcfs/libcfs/libcfs.a
LIBCFSUTIL= $(top_builddir)/libcfs/libcfs/libcfsutil.a

if UTILS
sbin_PROGRAMS = routerstat lst

if BUILD_DLC
sbin_PROGRAMS += lnetctl
endif

routerstat_SOURCES = routerstat.c

lst_SOURCES = lst.c
lst_LDADD = -L. -lptlctl $(LIBCFSUTIL) $(LIBCFS) $(LIBREADLINE) $(LIBEFENCE)
lst_DEPENDENCIES = libptlctl.a

if TESTS
sbin_PROGRAMS += wirecheck

wirecheck_SOURCES = wirecheck.c
endif

lib_LIBRARIES = libptlctl.a

libptlctl_a_SOURCES = portals.c debug.c

CYAML := $(top_builddir)/lnet/utils/cyaml/cyaml.c
lnetctl_SOURCES = lnetctl.c $(CYAML)
lnetctl_LDADD = -L. -lm -lyaml -llnetconfig \
		$(LIBCFSUTIL) $(LIBCFS) $(LIBREADLINE) $(LIBEFENCE)
lnetctl_DEPENDENCIES = $(top_builddir)/lnet/utils/lnetconfig/liblnetconfig.so
endif # UTILS
