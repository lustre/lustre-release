DEFS=
MODULE = obdclass
modulefs_DATA = obdclass.o
EXTRA_PROGRAMS = obdclass
LINX=page.c debug.c
obdclass_SOURCES = genops.c proc_lustre.c class_obd.c sysctl.c uuid.c $(LINX)

debug.c: 
	test -e debug.c || ln -sf $(top_srcdir)/lib/debug.c

page.c: 
	test -e page.c || ln -sf $(top_srcdir)/lib/page.c

include $(top_srcdir)/Rules
