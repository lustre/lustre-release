# Copyright (C) 2001  Cluster File Systems, Inc.
#
# This code is issued under the GNU General Public License.
# See the file COPYING in this distribution

DEFS= 
MODULE = obdfilter
modulefs_DATA = obdfilter.o
EXTRA_PROGRAMS = obdfilter

LINX=simple.c
simple.c:
	test -e simple.c || ln -sf $(top_srcdir)/lib/simple.c

FILTERC = filter.c
obdfilter_SOURCES = $(FILTERC) $(LINX)

dist-hook:
	list='$(LINX)'; for f in $$list; do rm -f $(distdir)/$$f; done

include $(top_srcdir)/Rules

