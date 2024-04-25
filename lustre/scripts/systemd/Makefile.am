# These are scripts that are generated from .in files
genunitfiles = lnet.service

if HAVE_SYSTEMD
systemdsystemunit_DATA = lnet.service
systemdsystemunit_SCRIPTS = lsvcgss.service
endif

EXTRA_DIST = $(addsuffix .in,$(genunitfiles)) lsvcgss.service

CLEANFILES = $(genunitfiles)

$(genunitfiles): %: %.in
	sed -e 's,@sbindir\@,$(sbindir),g' \
	    -e 's,@sysconfdir\@,$(sysconfdir),g' $< > $@
