# Copyright (C) 2001  Cluster File Systems, Inc.
#
# This code is issued under the GNU General Public License.
# See the file COPYING in this distribution

DEFS:= 

MODULE = mds
modulefs_DATA = mds.o
EXTRA_PROGRAMS = mds

LINX=mds_pack.c mds_updates.c
mds_pack.c: 
	ln -s ../lib/mds_pack.c .
mds_updates.c: 
	ln -s ../lib/mds_updates.c .

mds_SOURCES = handler.c mds_reint.c $(LINX)

dist-hook:
	list='$(LINX)'; for f in $$list; do rm -f $(distdir)/$$f; done

include $(top_srcdir)/Rules

