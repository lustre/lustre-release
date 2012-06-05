agent_PROGRAMS  = lustresnmp.so
mib_DATA = Lustre-MIB.txt

lustresnmp_so_SOURCES =		\
	lustre-snmp.c		\
	lustre-snmp.h		\
	lustre-snmp-trap.c	\
	lustre-snmp-trap.h	\
	lustre-snmp-util.c	\
	lustre-snmp-util.h

lustresnmp_so_LDADD := $(NET_SNMP_LIBS)
lustresnmp_so_CFLAGS := -fPIC $(NET_SNMP_CFLAGS)
lustresnmp_so_LDFLAGS = -fPIC -shared

SUBDIRS =
DIST_SUBDIRS = autoconf

EXTRA_DIST = $(mib_DATA)
