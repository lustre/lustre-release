# Copyright (C) 2001  Cluster File Systems, Inc.
#
# This code is issued under the GNU General Public License.
# See the file COPYING in this distribution

DEFS= 
MODULE = ost
modulefs_DATA = ost.o
EXTRA_PROGRAMS = ost

LINX=page.c obd_pack.c l_net.c ll_pack.c
ll_pack.c: 
	test -e ll_pack.c || ln -sf $(top_srcdir)/lib/ll_pack.c

obd_pack.c: 
	test -e obd_pack.c || ln -sf $(top_srcdir)/lib/obd_pack.c

page.c:
	test -e page.c || ln -sf $(top_srcdir)/lib/page.c

l_net.c:
	test -e l_net.c || ln -sf $(top_srcdir)/lib/l_net.c

ost_SOURCES = $(LINX) ost_handler.c
dist-hook:
	list='$(LINX)'; for f in $$list; do rm -f $(distdir)/$$f; done

include $(top_srcdir)/Rules

