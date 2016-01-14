agent_LTLIBRARIES = liblustresnmp.la
mib_DATA = Lustre-MIB.txt

liblustresnmp_la_SOURCES =	\
	lustre-snmp.c		\
	lustre-snmp.h		\
	lustre-snmp-trap.c	\
	lustre-snmp-trap.h	\
	lustre-snmp-util.c	\
	lustre-snmp-util.h

LIBCFS = $(top_builddir)/libcfs/libcfs/libcfs.a

liblustresnmp_la_CFLAGS := $(NET_SNMP_CFLAGS)
liblustresnmp_la_LIBADD := $(NET_SNMP_LIBS) $(LIBCFS)
liblustresnmp_la_LDFLAGS := -version-info 1:0:0

SUBDIRS =
DIST_SUBDIRS = autoconf

EXTRA_DIST = $(mib_DATA)
