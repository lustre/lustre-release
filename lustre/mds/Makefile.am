# Copyright (C) 2001  Cluster File Systems, Inc.
#
# This code is issued under the GNU General Public License.
# See the file COPYING in this distribution

DEFS:= 

MODULE = mds
modulefs_DATA = mds.o mds_ext2.o mds_ext3.o mds_extN.o
EXTRA_PROGRAMS = mds mds_ext2 mds_ext3 mds_extN

LINX=mds_updates.c simple.c
mds_updates.c: 
	test -e mds_updates.c || ln -sf $(top_srcdir)/lib/mds_updates.c

simple.c: 
	test -e simple.c || ln -sf $(top_srcdir)/lib/simple.c

mds_SOURCES = handler.c mds_reint.c mds_fs.c $(LINX)

dist-hook:
	list='$(LINX)'; for f in $$list; do rm -f $(distdir)/$$f; done

include $(top_srcdir)/Rules

