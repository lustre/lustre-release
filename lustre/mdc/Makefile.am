# Copyright (C) 2001  Cluster File Systems, Inc.
#
# This code is issued under the GNU General Public License.
# See the file COPYING in this distribution

DEFS=

if LIBLUSTRE
lib_LIBRARIES = libmdc.a
libmdc_a_SOURCES = mdc_request.c mdc_reint.c mdc_lib.c mdc_internal.h mdc_locks.c
else
MODULE = mdc
modulefs_DATA = mdc.o
EXTRA_PROGRAMS = mdc

mdc_SOURCES = mdc_request.c mdc_reint.c lproc_mdc.c mdc_lib.c mdc_locks.c mdc_internal.h
endif

include $(top_srcdir)/Rules
