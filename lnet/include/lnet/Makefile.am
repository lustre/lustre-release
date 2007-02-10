lnetdir=$(includedir)/lnet

SUBDIRS := linux
if DARWIN
SUBDIRS += darwin
endif
DIST_SUBDIRS := $(SUBDIRS)

EXTRA_DIST = api.h api-support.h \
	lib-lnet.h lib-types.h lnet.h lnetctl.h types.h \
        socklnd.h ptllnd.h ptllnd_wire.h
