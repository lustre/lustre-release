# Copyright (C) 2001  Cluster File Systems, Inc.
#
# This code is issued under the GNU General Public License.
# See the file COPYING in this distribution
DEFS= 
MODULE = lvfs


if EXTN
FSMOD = fsfilt_extN
else
FSMOD = fsfilt_ext3
endif


if LIBLUSTRE
noinst_LIBRARIES = liblvfs.a
liblvfs_a_SOURCES = lvfs_userfs.c
liblvfs_a_CFLAGS = -fPIC

#if MYSQL
#liblvfs_a_SOURCES += lvfs_user_mysql.c
#endif

else
modulefs_DATA = lvfs.o $(FSMOD).o fsfilt_reiserfs.o

EXTRA_PROGRAMS = lvfs $(FSMOD) fsfilt_reiserfs
lvfs_SOURCES = lvfs_common.c lvfs_linux.c fsfilt.c lvfs_internal.h
endif


include $(top_srcdir)/Rules
