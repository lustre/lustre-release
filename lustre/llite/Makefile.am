# Copyright (C) 2001  Cluster File Systems, Inc.
#
# This code is issued under the GNU General Public License.
# See the file COPYING in this distribution

DEFS= 

MODULE = llite
modulefs_DATA = llite.o
EXTRA_PROGRAMS = llite

COMMON_SRC = dcache.c dir.c file.c llite_close.c llite_lib.c llite_nfs.c rw.c \
             lproc_llite.c namei.c symlink.c sysctl.c llite_internal.h

if LINUX25
llite_SOURCES = $(COMMON_SRC) rw26.c super25.c
else
llite_SOURCES = $(COMMON_SRC) rw24.c super.c
endif

include $(top_srcdir)/Rules
