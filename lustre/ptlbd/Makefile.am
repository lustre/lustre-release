# Copyright (C) 2002  Cluster File Systems, Inc.
#
# This code is issued under the GNU General Public License.
# See the file COPYING in this distribution

DEFS=

MODULE = ptlbd
modulefs_DATA = ptlbd.o
EXTRA_PROGRAMS = ptlbd

ptlbd_SOURCES = blk.c client.c main.c rpc.c server.c

include $(top_srcdir)/Rules

CFLAGS += -DOBD_MAX_IOCTL_BUFFER=@OBD_BUFFER_SIZE@
