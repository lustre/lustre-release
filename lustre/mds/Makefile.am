# Copyright (C) 2001  Cluster File Systems, Inc.
#
# This code is issued under the GNU General Public License.
# See the file COPYING in this distribution

DEFS= 

if LINUX25
FSMOD = mds_ext3
else
FSMOD = mds_extN
endif

MODULE = mds
modulefs_DATA = mds.o $(FSMOD).o
EXTRA_PROGRAMS = mds $(FSMOD)

LINX= mds_updates.c simple.c ll_pack.c target.c

ll_pack.c: 
	test -e ll_pack.c || ln -sf $(top_srcdir)/lib/ll_pack.c
mds_updates.c: 
	test -e mds_updates.c || ln -sf $(top_srcdir)/lib/mds_updates.c
simple.c: 
	test -e simple.c || ln -sf $(top_srcdir)/lib/simple.c
target.c: 
	test -e target.c || ln -sf $(top_srcdir)/lib/target.c

mds_SOURCES = mds_lov.c handler.c mds_reint.c mds_fs.c lproc_mds.c $(LINX)

include $(top_srcdir)/Rules
