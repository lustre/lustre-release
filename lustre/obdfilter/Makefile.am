# Copyright (C) 2001  Cluster File Systems, Inc.
#
# This code is issued under the GNU General Public License.
# See the file COPYING in this distribution

DEFS= 
MODULE = obdfilter
modulefs_DATA = obdfilter.o
EXTRA_PROGRAMS = obdfilter

LINX=simple.c ll_pack.c
ll_pack.c:
	test -e ll_pack.c || ln -sf $(top_srcdir)/lib/ll_pack.c

simple.c:
	test -e simple.c || ln -sf $(top_srcdir)/lib/simple.c

FILTERC = filter.c
obdfilter_SOURCES = $(FILTERC) $(LINX)

dist-hook:
	list='$(LINX)'; for f in $$list; do rm -f $(distdir)/$$f; done

distclean: 
	$(RM) Makefile.in

include $(top_srcdir)/Rules

