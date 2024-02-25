# SPDX-License-Identifier: GPL-2.0

#
# Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
# Use is subject to license terms.
#
# Copyright (c) 2013, 2015, Intel Corporation.
#

#
# This file is part of Lustre, http://www.lustre.org/
#

AM_CFLAGS  := -fPIC -D_GNU_SOURCE $(UTILS_CFLAGS) $(LIBNL3_CFLAGS)
AM_LDFLAGS := -L. $(UTILS_LDFLAGS)

SUBDIRS = lnetconfig

if UTILS
sbin_PROGRAMS = routerstat lst lnetctl

routerstat_SOURCES = routerstat.c
routerstat_LDADD = $(top_builddir)/lnet/utils/lnetconfig/liblnetconfig.la

lst_SOURCES = lst.c
lst_CFLAGS = -fPIC -D_LINUX_TIME_H -D_GNU_SOURCE $(LIBNL3_CFLAGS)
lst_LDADD = $(top_builddir)/lnet/utils/lnetconfig/liblnetconfig.la \
	    $(LIBEFENCE) $(LIBNL3_LIBS) -lyaml

if TESTS
sbin_PROGRAMS += wirecheck

wirecheck_SOURCES = wirecheck.c
endif # TESTS

lnetctl_SOURCES = lnetctl.c
lnetctl_LDADD = $(top_builddir)/lnet/utils/lnetconfig/liblnetconfig.la \
		$(LIBNL3_LIBS) -lyaml $(LIBEFENCE)
endif # UTILS
