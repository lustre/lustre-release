# Copyright (C) 2001  Cluster File Systems, Inc.
#
# This code is issued under the GNU General Public License.
# See the file COPYING in this distribution

DEFS=


if LIBLUSTRE
lib_LIBRARIES = libosc.a
LINX= obd_pack.c
libosc_a_SOURCES = osc_request.c  $(LINX)
else
MODULE = osc
modulefs_DATA = osc.o
EXTRA_PROGRAMS = osc
LINX= obd_pack.c client.c
osc_SOURCES = osc_request.c lproc_osc.c $(LINX)
endif

obd_pack.c: 
	test -e obd_pack.c || ln -sf $(top_srcdir)/lib/obd_pack.c
client.c: 
	test -e client.c || ln -sf $(top_srcdir)/lib/client.c

dist-hook:
	list='$(LINX)'; for f in $$list; do rm -f $(distdir)/$$f; done

include $(top_srcdir)/Rules
