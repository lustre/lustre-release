# Copyright (C) 2001  Cluster File Systems, Inc.
#
# This code is issued under the GNU General Public License.
# See the file COPYING in this distribution

DEFS= 

MODULE = llite
modulefs_DATA = llite.o
EXTRA_PROGRAMS = llite

llite_SOURCES = dcache.c dir.c file.c llite_close.c llite_lib.c llite_nfs.c
llite_SOURCES += lproc_llite.c namei.c rw.c rw24.c super.c super25.c
llite_SOURCES += symlink.c sysctl.c llite_internal.h

include $(top_srcdir)/Rules
