# Copyright (C) 2001  Cluster File Systems, Inc.
#
# This code is issued under the GNU General Public License.
# See the file COPYING in this distribution

#
# ldlm is built into ptlrpc
#

DEFS= 

if LIBLUSTRE
lib_LIBRARIES = libldlm.a
libldlm_a_SOURCES = l_lock.c ldlm_lock.c ldlm_resource.c ldlm_lib.c \
  ldlm_plain.c ldlm_extent.c ldlm_request.c ldlm_lockd.c ldlm_internal.h
endif

include $(top_srcdir)/Rules
