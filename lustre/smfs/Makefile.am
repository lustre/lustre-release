# Copyright (C) 2001  Cluster File Systems, Inc.
#
# This code is issued under the GNU General Public License.
# See the file COPYING in this distribution


DEFS= 

MODULE = smfs
modulefs_DATA = smfs.o
EXTRA_PROGRAMS = smfs

smfs_SOURCES = super.c options.c inode.c cache.c dir.c sysctl.c file.c 
smfs_SOURCES += symlink.c sm_fs.c kml.c reint.c journal.c journal_ext3.c
smfs_SOURCES += smfs_llog.c
include $(top_srcdir)/Rules
