# Copyright (C) 2001  Cluster File Systems, Inc.
#
# This code is issued under the GNU General Public License.
# See the file COPYING in this distribution

DEFS=

LDLM_COMM_SOURCES= $(top_srcdir)/ldlm/l_lock.c $(top_srcdir)/ldlm/ldlm_lock.c \
    $(top_srcdir)/ldlm/ldlm_resource.c $(top_srcdir)/ldlm/ldlm_lib.c          \
    $(top_srcdir)/ldlm/ldlm_plain.c $(top_srcdir)/ldlm/ldlm_extent.c          \
    $(top_srcdir)/ldlm/ldlm_request.c $(top_srcdir)/ldlm/ldlm_lockd.c         \
    $(top_srcdir)/ldlm/ldlm_internal.h

COMMON_SOURCES =  client.c recover.c connection.c niobuf.c pack_generic.c   \
    events.c ptlrpc_module.c service.c pinger.c recov_thread.c llog_net.c   \
    llog_client.c llog_server.c import.c ptlrpcd.c ptlrpc_internal.h        \
    $(LDLM_COMM_SOURCES)

if LIBLUSTRE

noinst_LIBRARIES = libptlrpc.a
libptlrpc_a_CFLAGS = -fPIC
libptlrpc_a_SOURCES = $(COMMON_SOURCES)

else

MODULE = ptlrpc
modulefs_DATA = ptlrpc.o
EXTRA_PROGRAMS = ptlrpc

ptlrpc_SOURCES = $(top_srcdir)/ldlm/ldlm_flock.c $(COMMON_SOURCES) \
    lproc_ptlrpc.c

endif

ptlrpc_DEPENDENCIES=symlinks

symlinks:
	ln -sf $(subst /ldlm/,/ptlrpc/,$(addsuffix .o,$(basename $(LDLMSOURCES)))) ../ldlm

include $(top_srcdir)/Rules
