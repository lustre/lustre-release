# Copyright (C) 2001  Cluster File Systems, Inc.
#
# This code is issued under the GNU General Public License.
# See the file COPYING in this distribution

DEFS=

LDLMSOURCES= $(top_srcdir)/ldlm/l_lock.c $(top_srcdir)/ldlm/ldlm_lock.c \
   $(top_srcdir)/ldlm/ldlm_resource.c $(top_srcdir)/ldlm/ldlm_lib.c     \
   $(top_srcdir)/ldlm/ldlm_plain.c $(top_srcdir)/ldlm/ldlm_extent.c     \
   $(top_srcdir)/ldlm/ldlm_flock.c $(top_srcdir)/ldlm/ldlm_request.c    \
   $(top_srcdir)/ldlm/ldlm_lockd.c $(top_srcdir)/ldlm/ldlm_internal.h

if LIBLUSTRE

lib_LIBRARIES = libptlrpc.a
libptlrpc_a_SOURCES = client.c niobuf.c pack_generic.c recover.c connection.c \
ptlrpc_module.c events.c service.c pinger.c import.c \
recov_thread.c llog_net.c llog_client.c $(LDLMSOURCES)

else

MODULE = ptlrpc
modulefs_DATA = ptlrpc.o
EXTRA_PROGRAMS = ptlrpc

ptlrpc_SOURCES = recover.c connection.c ptlrpc_module.c events.c service.c \
   client.c niobuf.c pack_generic.c lproc_ptlrpc.c pinger.c                \
   ptlrpc_internal.h recov_thread.c import.c llog_net.c llog_server.c      \
   llog_client.c $(LDLMSOURCES)
endif

ptlrpc_DEPENDENCIES=symlinks

symlinks:
	ln -sf $(subst /ldlm/,/ptlrpc/,$(addsuffix .o,$(basename $(LDLMSOURCES)))) ../ldlm

include $(top_srcdir)/Rules
