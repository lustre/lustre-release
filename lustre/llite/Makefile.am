# Copyright (C) 2001  Cluster File Systems, Inc.
#
# This code is issued under the GNU General Public License.
# See the file COPYING in this distribution

DEFS:= 

MODULE = llight
modulefs_DATA = llight.o
EXTRA_PROGRAMS = llight

page.c: 
	ln -s ../lib/page.c


llight_SOURCES =  page.c super.c rw.c file.c dir.c sysctl.c namei.c symlink.c

include $(top_srcdir)/Rules
