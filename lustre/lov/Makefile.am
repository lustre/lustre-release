# Copyright (C) 2002 Cluster File Systems, Inc.
#
# This code is issued under the GNU General Public License.
# See the file COPYING in this distribution

DEFS=

if LIBLUSTRE
lib_LIBRARIES = liblov.a
liblov_a_SOURCES = lov_obd.c lov_pack.c
else
MODULE = lov
modulefs_DATA = lov.o
EXTRA_PROGRAMS = lov
lov_SOURCES = lov_obd.c lov_pack.c lproc_lov.c
endif

include $(top_srcdir)/Rules
