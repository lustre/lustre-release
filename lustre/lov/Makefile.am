# Copyright (C) 2002 Cluster File Systems, Inc.
#
# This code is issued under the GNU General Public License.
# See the file COPYING in this distribution

DEFS=

if LIBLUSTRE
lib_LIBRARIES = liblov.a
LINX=client.c
liblov_a_SOURCES = lov_obd.c lov_pack.c $(LINX)
else
MODULE = lov
modulefs_DATA = lov.o
EXTRA_PROGRAMS = lov
LINX=client.c
lov_SOURCES = lov_obd.c lov_pack.c lproc_lov.c $(LINX)
endif


client.c: 
	test -e client.c || ln -sf $(top_srcdir)/lib/client.c

include $(top_srcdir)/Rules
