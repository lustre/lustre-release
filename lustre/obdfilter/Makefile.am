# Copyright (C) 2001  Cluster File Systems, Inc.
#
# This code is issued under the GNU General Public License.
# See the file COPYING in this distribution

MODULE = obdfilter
modulefs_DATA = obdfilter.o
EXTRA_PROGRAMS = obdfilter

COMMON_SRC = filter.c filter_io.c filter_log.c filter_san.c lproc_obdfilter.c \
             filter_internal.h filter_lvb.c

if LINUX25
obdfilter_SOURCES = $(COMMON_SRC) filter_io_26.c
else
obdfilter_SOURCES = $(COMMON_SRC) filter_io_24.c
endif

include $(top_srcdir)/Rules
