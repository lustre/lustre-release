# Copyright (C) 2001  Cluster File Systems, Inc.
#
# This code is issued under the GNU General Public License.
# See the file COPYING in this distribution

DEFS:=

MODULE = mdc
modulefs_DATA = mdc.o
EXTRA_PROGRAMS = mdc

LINX=mds_updates.c
mdc_SOURCES =  mdc_request.c mdc_reint.c $(LINX)

mds_updates.c: 
	test -e mds_updates.c || ln -sf $(top_srcdir)/lib/mds_updates.c .

dist-hook:
	list='$(LINX)'; for f in $$list; do rm -f $(distdir)/$$f; done


include $(top_srcdir)/Rules
