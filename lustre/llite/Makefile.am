# Copyright (C) 2001  Cluster File Systems, Inc.
#
# This code is issued under the GNU General Public License.
# See the file COPYING in this distribution

DEFS= 

MODULE = llite
modulefs_DATA = llite.o
EXTRA_PROGRAMS = llite

LINX= ll_pack.c

llite_SOURCES = dcache.c commit_callback.c super.c rw.c super25.c
llite_SOURCES += file.c dir.c sysctl.c symlink.c $(LINX)
llite_SOURCES += lov_pack.c recover.c namei.c lproc_llite.c

lov_pack.c: 
	test -e lov_pack.c || ln -sf $(top_srcdir)/lib/lov_pack.c .
ll_pack.c:
	test -e ll_pack.c || ln -sf $(top_srcdir)/lib/ll_pack.c .

include $(top_srcdir)/Rules
