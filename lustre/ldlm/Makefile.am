# Copyright (C) 2001  Cluster File Systems, Inc.
#
# This code is issued under the GNU General Public License.
# See the file COPYING in this distribution

DEFS= 

CFLAGS = -DOBD_MAX_IOCTL_BUFFER=@OBD_BUFFER_SIZE@

LDLMSOURCES= l_lock.c ldlm_lock.c ldlm_resource.c ldlm_lib.c \
ldlm_extent.c ldlm_request.c ldlm_lockd.c

if LIBLUSTRE
lib_LIBRARIES = libldlm.a
libldlm_a_SOURCES = $(LDLMSOURCES)
else
MODULE = ldlm
modulefs_DATA = ldlm.o
EXTRA_PROGRAMS = ldlm

ldlm_SOURCES = $(LDLMSOURCES)
endif

include $(top_srcdir)/Rules

CFLAGS += -DOBD_MAX_IOCTL_BUFFER=@OBD_BUFFER_SIZE@
