# These are scripts that are generated from .in files
genunitfiles = lnet.service

if HAVE_SYSTEMD
systemdsystemunit_DATA = lnet.service
endif

EXTRA_DIST = $(addsuffix .in,$(genunitfiles))

CLEANFILES = $(genunitfiles)

$(genunitfiles): %: %.in
	sed -e 's,@sbindir\@,$(sbindir),g' \
	    -e 's,@sysconfdir\@,$(sysconfdir),g' $< > $@
