# Copyright (C) 2002 Cluster File Systems, Inc.
#
# This code is issued under the GNU General Public License.
# See the file COPYING in this distribution

DEFS=

if LIBLUSTRE
lib_LIBRARIES = liblmv.a
liblmv_a_SOURCES = lmv_obd.c lmv_intent.c lmv_objmgr.c
else
MODULE = lmv
modulefs_DATA = lmv.o
EXTRA_PROGRAMS = lmv
lmv_SOURCES = lmv_obd.c lmv_intent.c lmv_objmgr.c
endif

include $(top_srcdir)/Rules
