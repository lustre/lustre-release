# Copyright (C) 2001  Cluster File Systems, Inc.
#
# This code is issued under the GNU General Public License.
# See the file COPYING in this distribution

DEFS=

if LIBLUSTRE
lib_LIBRARIES = libosc.a
libosc_a_SOURCES = osc_request.c
else
MODULE = osc
modulefs_DATA = osc.o
EXTRA_PROGRAMS = osc
osc_SOURCES = osc_request.c lproc_osc.c osc_lib.c
endif

include $(top_srcdir)/Rules
