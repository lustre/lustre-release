# Copyright (C) 2001  Cluster File Systems, Inc.
#
# This code is issued under the GNU General Public License.
# See the file COPYING in this distribution

DEFS=

if LIBLUSTRE
noinst_LIBRARIES = libosc.a
libosc_a_SOURCES = osc_request.c osc_lib.c osc_create.c osc_rpcd.c osc_internal.h
libosc_a_CFLAGS = -fPIC
else
MODULE = osc
modulefs_DATA = osc.o
EXTRA_PROGRAMS = osc
osc_SOURCES = osc_request.c lproc_osc.c osc_lib.c  osc_create.c osc_rpcd.c osc_internal.h
endif

include $(top_srcdir)/Rules
