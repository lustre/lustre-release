# Copyright (C) 2001  Cluster File Systems, Inc.
#
# This code is issued under the GNU General Public License.
# See the file COPYING in this distribution

DEFS=

MODULE = osc
modulefs_DATA = osc.o
EXTRA_PROGRAMS = osc

LINX= obd_pack.c ll_pack.c
osc_SOURCES = osc_request.c $(LINX)

obd_pack.c: 
	test -e obd_pack.c || ln -sf $(top_srcdir)/lib/obd_pack.c

ll_pack.c: 
	test -e ll_pack.c || ln -sf $(top_srcdir)/lib/ll_pack.c

dist-hook:
	list='$(LINX)'; for f in $$list; do rm -f $(distdir)/$$f; done

include $(top_srcdir)/Rules
