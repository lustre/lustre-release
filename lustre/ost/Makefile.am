# Copyright (C) 2001  Cluster File Systems, Inc.
#
# This code is issued under the GNU General Public License.
# See the file COPYING in this distribution

DEFS= 
MODULE = ost
modulefs_DATA = ost.o
EXTRA_PROGRAMS = ost

LINX=obd_pack.c target.c

obd_pack.c: 
	test -e obd_pack.c || ln -sf $(top_srcdir)/lib/obd_pack.c
target.c: 
	test -e target.c || ln -sf $(top_srcdir)/lib/target.c

ost_SOURCES = ost_handler.c lproc_ost.c $(LINX)
dist-hook:
	list='$(LINX)'; for f in $$list; do rm -f $(distdir)/$$f; done

include $(top_srcdir)/Rules
