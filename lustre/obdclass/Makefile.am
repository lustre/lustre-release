DEFS=
MODULE = obdclass
modulefs_DATA = obdclass.o
EXTRA_PROGRAMS = obdclass
obdclass_SOURCES = genops.c proc_lustre.c class_obd.c sysctl.c page.c

page.c: 
	test -e page.c || ln -sf $(top_srcdir)/lib/page.c

include $(top_srcdir)/Rules
