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

## $(srcdir)/../ for <portals/*.h>, ../../ for generated <config.h>
#COMPILE = $(CC) -Wall -g -I$(srcdir)/../include -I../../include
#LINK = $(CC) -o $@

LIBCFS= $(top_builddir)/libcfs/libcfs/libcfs.a
LIBCFSUTIL= $(top_builddir)/libcfs/libcfs/libcfsutil.a

if LIBLUSTRE
noinst_LIBRARIES = libuptlctl.a
endif

libuptlctl_a_SOURCES = portals.c debug.c
libuptlctl_a_CPPFLAGS = $(LLCPPFLAGS)
libuptlctl_a_CFLAGS = $(LLCFLAGS) -DLUSTRE_UTILS=1

sbin_PROGRAMS = debugctl

lib_LIBRARIES = libptlctl.a

if LIBLUSTRE
noinst_LIBRARIES += liblst.a
liblst_a_SOURCES =
endif

libptlctl_a_SOURCES = portals.c debug.c

if UTILS
sbin_PROGRAMS += ptlctl routerstat wirecheck lst
if LIBLUSTRE
sbin_PROGRAMS += lstclient
endif
endif

wirecheck_SOURCES = wirecheck.c

ptlctl_SOURCES = ptlctl.c
ptlctl_LDADD =  -L. -lptlctl $(LIBCFSUTIL) $(LIBCFS) $(LIBREADLINE) $(LIBEFENCE)
ptlctl_DEPENDENCIES = libptlctl.a

routerstat_SOURCES = routerstat.c

debugctl_SOURCES = debugctl.c
debugctl_LDADD = -L. -lptlctl $(LIBCFSUTIL) $(LIBREADLINE) $(LIBEFENCE)
debugctl_DEPENDENCIES = libptlctl.a

lst_SOURCES = lst.c
lst_LDADD = -L. -lptlctl $(LIBCFSUTIL) $(LIBCFS) $(LIBREADLINE) $(LIBEFENCE)
lst_DEPENDENCIES = libptlctl.a

LND_LIBS =
if BUILD_USOCKLND
LND_LIBS +=    $(top_builddir)/lnet/ulnds/socklnd/libsocklnd.a
endif

if LIBLUSTRE
LIB_SELFTEST = $(top_builddir)/libcfs/libcfs/libcfs.a $(top_builddir)/lnet/lnet/liblnet.a $(top_builddir)/lnet/selftest/libselftest.a

export AR
export RANLIB

liblst.a : $(LIB_SELFTEST) $(LND_LIBS)
	sh $(srcdir)/genlib.sh "$(LIBS)" "$(LND_LIBS)" "$(PTHREAD_LIBS)"

lstclient_SOURCES = lstclient.c
lstclient_LDADD = -L. -lptlctl -llst $(LIBREADLINE) $(LIBEFENCE) $(PTHREAD_LIBS)
lstclient_DEPENDENCIES = libptlctl.a liblst.a
endif

EXTRA_DIST = genlib.sh
