# Copyright (C) 2001  Cluster File Systems, Inc.
#
# This code is issued under the GNU General Public License.
# See the file COPYING in this distribution

DEFS:= 

MODULE = mds
modulefs_DATA = mds.o mds_extN.o # mds_ext2.o mds_ext3.o
EXTRA_PROGRAMS = mds mds_extN # mds_ext2 mds_ext3

LINX=mds_updates.c simple.c ll_pack.c l_net.c
ll_pack.c: 
	test -e ll_pack.c || ln -sf $(top_srcdir)/lib/ll_pack.c

mds_updates.c: 
	test -e mds_updates.c || ln -sf $(top_srcdir)/lib/mds_updates.c

simple.c: 
	test -e simple.c || ln -sf $(top_srcdir)/lib/simple.c

l_net.c: 
	test -e l_net.c || ln -sf $(top_srcdir)/lib/l_net.c

mds_SOURCES = handler.c mds_reint.c mds_fs.c $(LINX)

dist-hook:
	list='$(LINX)'; for f in $$list; do rm -f $(distdir)/$$f; done

include $(top_srcdir)/Rules

