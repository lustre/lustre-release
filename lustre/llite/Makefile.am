# Copyright (C) 2001  Cluster File Systems, Inc.
#
# This code is issued under the GNU General Public License.
# See the file COPYING in this distribution

DEFS= 

MODULE = llite
modulefs_DATA = llite.o
EXTRA_PROGRAMS = llite

llite_SOURCES = dcache.c commit_callback.c super.c rw.c iod.c super25.c
llite_SOURCES += file.c dir.c sysctl.c symlink.c
llite_SOURCES += namei.c lproc_llite.c llite_internal.h

include $(top_srcdir)/Rules
