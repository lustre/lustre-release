# Copyright (C) 2001  Cluster File Systems, Inc.
#
# This code is issued under the GNU General Public License.
# See the file COPYING in this distribution

DEFS= 

MODULE = mds
modulefs_DATA = mds.o mds_extN.o # mds_ext2.o mds_ext3.o
EXTRA_PROGRAMS = mds mds_extN # mds_ext2 mds_ext3

LINX= mds_updates.c simple.c ll_pack.c lov_pack.c

ll_pack.c: 
	test -e ll_pack.c || ln -sf $(top_srcdir)/lib/ll_pack.c
mds_updates.c: 
	test -e mds_updates.c || ln -sf $(top_srcdir)/lib/mds_updates.c
simple.c: 
	test -e simple.c || ln -sf $(top_srcdir)/lib/simple.c
lov_pack.c: 
	test -e lov_pack.c || ln -sf $(top_srcdir)/lib/lov_pack.c

mds_SOURCES = mds_lov.c handler.c mds_reint.c mds_fs.c $(LINX) ../lib/target.c

include $(top_srcdir)/Rules

