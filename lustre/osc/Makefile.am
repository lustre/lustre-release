# Copyright (C) 2001  Cluster File Systems, Inc.
#
# This code is issued under the GNU General Public License.
# See the file COPYING in this distribution

DEFS:=

MODULE = osc
modulefs_DATA = osc.o
EXTRA_PROGRAMS = osc

LINX= obd_pack.c 
osc_SOURCES =  obd_pack.c osc_request.c # super.c rw.c file.c dir.c sysctl.c super.c namei.c symlink.c

obd_pack.c: 
	ln -s ../lib/obd_pack.c .

dist-hook:
	list='$(LINX)'; for f in $$list; do rm -f $(distdir)/$$f; done

include $(top_srcdir)/Rules
