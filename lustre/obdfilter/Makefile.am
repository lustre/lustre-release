# Copyright (C) 2001  Cluster File Systems, Inc.
#
# This code is issued under the GNU General Public License.
# See the file COPYING in this distribution

DEFS:= 
MODULE = obdfilter
modulefs_DATA = obdfilter.o
EXTRA_PROGRAMS = obdfilter

LINX=page.c simple.c
simple.c:
	test -e simple.c || ln -sf $(top_srcdir)/lib/simple.c
page.c:
	test -e page.c || ln -sf $(top_srcdir)/lib/page.c

EXT2C = filter.c
obdfilter_SOURCES = filter.c $(LINX)

dist-hook:
	list='$(LINX)'; for f in $$list; do rm -f $(distdir)/$$f; done

include $(top_srcdir)/Rules

