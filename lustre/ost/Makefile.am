# Copyright (C) 2001  Cluster File Systems, Inc.
#
# This code is issued under the GNU General Public License.
# See the file COPYING in this distribution

DEFS= 

MODULE = ost
modulefs_DATA = ost.o
EXTRA_PROGRAMS = ost
ost_SOURCES = ost_handler.c lproc_ost.c

include $(top_srcdir)/Rules

CFLAGS += -DOBD_MAX_IOCTL_BUFFER=@OBD_BUFFER_SIZE@
