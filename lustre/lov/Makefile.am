# Copyright (C) 2002 Cluster File Systems, Inc.
#
# This code is issued under the GNU General Public License.
# See the file COPYING in this distribution

DEFS=

if LIBLUSTRE
noinst_LIBRARIES = liblov.a
liblov_a_SOURCES = lov_log.c lov_obd.c lov_pack.c lov_internal.h
liblov_a_CFLAGS = -fPIC
else
MODULE = lov
modulefs_DATA = lov.o
EXTRA_PROGRAMS = lov
lov_SOURCES = lov_log.c lov_obd.c lov_pack.c lproc_lov.c lov_internal.h
endif

include $(top_srcdir)/Rules
