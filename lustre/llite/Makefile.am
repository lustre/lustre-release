# Copyright (C) 2001  Cluster File Systems, Inc.
#
# This code is issued under the GNU General Public License.
# See the file COPYING in this distribution

MODULE = llight
modulefs_DATA = llight.o
EXTRA_PROGRAMS = llight


llight_SOURCES =  mds_pack.c request.c # super.c rw.c file.c dir.c sysctl.c super.c namei.c symlink.c

mds_pack.c: 
	ln -s ../lib/mds_pack.c .


include $(top_srcdir)/Rules
