# Copyright (C) 2001  Cluster File Systems, Inc.
#
# This code is issued under the GNU General Public License.
# See the file COPYING in this distribution

DEFS= 

MODULE = mds
modulefs_DATA = mds.o
EXTRA_PROGRAMS = mds

mds_pack.c: 
	ln -s ../lib/mds_pack.c .

mds_SOURCES = mds_pack.c handler.c 

include $(top_srcdir)/Rules

