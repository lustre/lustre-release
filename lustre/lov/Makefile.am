# Copyright (C) 2002 Cluster File Systems, Inc.
#
# This code is issued under the GNU General Public License.
# See the file COPYING in this distribution

DEFS=

MODULE = lov
modulefs_DATA = lov.o
EXTRA_PROGRAMS = lov
LINX= lov_pack.c

lov_SOURCES = lov_obd.c lproc_lov.c $(LINX)

lov_pack.c: 
	test -e lov_pack.c || ln -sf $(top_srcdir)/lib/lov_pack.c

include $(top_srcdir)/Rules
