# Copyright (C) 2001  Cluster File Systems, Inc.
#
# This code is issued under the GNU General Public License.
# See the file COPYING in this distribution

DEFS= 

if LIBLUSTRE
lib_LIBRARIES = libobdecho.a
libobdecho_a_SOURCES = echo_client.c 
else
MODULE = obdecho
modulefs_DATA = obdecho.o
EXTRA_PROGRAMS = obdecho
LINX=
obdecho_SOURCES = echo.c echo_client.c lproc_echo.c $(LINX)
endif

include $(top_srcdir)/Rules

