# SPDX-License-Identifier: GPL-2.0

#
# This file is part of Lustre, http://www.lustre.org/
#

noinst_LTLIBRARIES = libcfs.la
libcfs_la_SOURCES  := string.c nidstrings.c param.c
if UTILS
libcfs_la_SOURCES  += parser.c l_ioctl.c
endif
libcfs_la_CPPFLAGS := -D_GNU_SOURCE
libcfs_la_CPPFLAGS += -D_LARGEFILE64_SOURCE=1 -D_FILE_OFFSET_BITS=64
if UTILS
libcfs_la_CPPFLAGS += -DLUSTRE_UTILS=1
endif
libcfs_la_CFLAGS := -fPIC

EXTRA_DIST = \
	l_ioctl.c \
	nidstrings.c \
	param.c \
	parser.c \
	string.c
