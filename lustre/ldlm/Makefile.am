# Copyright (C) 2001  Cluster File Systems, Inc.
#
# This code is issued under the GNU General Public License.
# See the file COPYING in this distribution

DEFS:= 
MODULE = ldlm
modulefs_DATA = ldlm.o
EXTRA_PROGRAMS = ldlm

pack_generic.c:
	ln -s ../lib/pack_generic.c
ldlm_SOURCES = ldlm_lock.c ldlm_resource.c ldlm_test.c ldlm_lockd.c \
ldlm_extent.c pack_generic.c

include $(top_srcdir)/Rules

