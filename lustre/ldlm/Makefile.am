# Copyright (C) 2001  Cluster File Systems, Inc.
#
# This code is issued under the GNU General Public License.
# See the file COPYING in this distribution

DEFS:= 
MODULE = ldlm
modulefs_DATA = ldlm.o
EXTRA_PROGRAMS = ldlm

l_lock.c: 
	test -e l_lock.c || ln -sf $(top_srcdir)/lib/l_lock.c

LINX=l_lock.c

ldlm_SOURCES = l_lock.c ldlm_lock.c ldlm_resource.c ldlm_test.c ldlm_lockd.c \
ldlm_extent.c ldlm_request.c


include $(top_srcdir)/Rules

