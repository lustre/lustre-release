# Copyright (C) 2001  Cluster File Systems, Inc.
#
# This code is issued under the GNU General Public License.
# See the file COPYING in this distribution


DEFS= 
SUBDIRS = . utils

MODULE = snapfs
modulefs_DATA = snapfs.o
EXTRA_PROGRAMS = snapfs

snapfs_SOURCES = cache.c  clonefs.c  dcache.c  dir.c  dotsnap.c  file.c 
snapfs_SOURCES += filter.c  inode.c  journal_ext3.c  psdev.c 
snapfs_SOURCES += snap.c  snaptable.c  super.c  symlink.c  sysctl.c options.c


include $(top_srcdir)/Rules
