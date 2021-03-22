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
# http://www.gnu.org/licenses/gpl-2.0.html
#
# GPL HEADER END
#

#
# Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
# Use is subject to license terms.
#
# Copyright (c) 2013, 2015, Intel Corporation.
#

#
# This file is part of Lustre, http://www.lustre.org/
#

AM_CFLAGS  := -fPIC -D_GNU_SOURCE $(UTILS_CFLAGS)
AM_LDFLAGS := -L. $(UTILS_LDFLAGS)

SUBDIRS = lnetconfig

if UTILS
sbin_PROGRAMS = routerstat lst lnetctl

routerstat_SOURCES = routerstat.c
routerstat_LDADD = $(top_builddir)/lnet/utils/lnetconfig/liblnetconfig.la

lst_SOURCES = lst.c
lst_CFLAGS = -fPIC -D_LINUX_TIME_H -D_GNU_SOURCE
lst_LDADD = $(top_builddir)/lnet/utils/lnetconfig/liblnetconfig.la \
	    $(LIBEFENCE)

if TESTS
sbin_PROGRAMS += wirecheck

wirecheck_SOURCES = wirecheck.c
endif # TESTS

lnetctl_SOURCES = lnetctl.c
lnetctl_LDADD = $(top_builddir)/lnet/utils/lnetconfig/liblnetconfig.la \
		$(LIBEFENCE)
endif # UTILS
