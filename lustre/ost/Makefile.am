# Copyright (C) 2001  Cluster File Systems, Inc.
#
# This code is issued under the GNU General Public License.
# See the file COPYING in this distribution

DEFS:= 
MODULE = ost
modulefs_DATA = ost.o
EXTRA_PROGRAMS = ost

obd_pack.c: 
	ln -s ../lib/obd_pack.c .

ost_SOURCES = obd_pack.c ost_handler.c

include $(top_srcdir)/Rules

