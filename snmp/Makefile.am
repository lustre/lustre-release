agent_LTLIBRARIES = lustresnmp.la
mib_DATA = Lustre-MIB.txt

lustresnmp_la_SOURCES =		\
	lustre-snmp.c		\
	lustre-snmp.h		\
	lustre-snmp-trap.c	\
	lustre-snmp-trap.h	\
	lustre-snmp-util.c	\
	lustre-snmp-util.h

lustresnmp_la_LIBADD := $(NET_SNMP_LIBS)
lustresnmp_la_CFLAGS := -fPIC $(NET_SNMP_CFLAGS)
lustresnmp_la_LDFLAGS = -fPIC -shared -module -avoid-version

SUBDIRS =
DIST_SUBDIRS = autoconf

EXTRA_DIST = $(mib_DATA)
