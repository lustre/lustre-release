# Copyright (C) 2001  Cluster File Systems, Inc.
#
# This code is issued under the GNU General Public License.
# See the file COPYING in this distribution

DEFS:=

MODULE = mdc
modulefs_DATA = mdc.o
EXTRA_PROGRAMS = mdc


mdc_SOURCES =  mds_pack.c mdc_request.c mdc_reint.c mds_updates.c

mds_pack.c: 
	ln -s ../lib/mds_pack.c .
mds_updates.c: 
	ln -s ../lib/mds_updates.c .

include $(top_srcdir)/Rules
