# Copyright (C) 2001  Cluster File Systems, Inc.
#
# This code is issued under the GNU General Public License.
# See the file COPYING in this distribution

DEFS= 

if LIBLUSTRE
lib_LIBRARIES = libldlm.a
libldlm_a_SOURCES = l_lock.c ldlm_lock.c ldlm_resource.c  \
ldlm_extent.c ldlm_request.c # ldlm_lockd.c
else
MODULE = ldlm
modulefs_DATA = ldlm.o
EXTRA_PROGRAMS = ldlm

ldlm_SOURCES = l_lock.c ldlm_lock.c ldlm_resource.c  \
ldlm_extent.c ldlm_request.c ldlm_lockd.c
endif

include $(top_srcdir)/Rules


