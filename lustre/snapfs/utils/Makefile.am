# Administration utilities Makefile

if SNAPFS
noinst_PROGRAMS = snapconf
snapconf_LDADD := $(LIBREADLINE)  -ltermcap
endif

snapconf_SOURCES = parser.c snapctl.c snapconf.c parser.h snapctl.h
