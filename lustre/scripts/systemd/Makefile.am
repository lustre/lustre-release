# These are scripts that are generated from .in files
genunitfiles = lnet.service

if HAVE_SYSTEMD
systemdsystemunit_DATA = lnet.service
endif

EXTRA_DIST = $(addsuffix .in,$(genunitfiles))

CLEANFILES = $(genunitfiles)

$(genunitfiles): %: %.in
if BUILD_DLC
	sed -e 's,@sbindir\@,$(sbindir),g' \
	    -e 's,@sysconfdir\@,$(sysconfdir),g' \
	    -e 's,@BUILD_DLC_TRUE\@,,g' \
	    -e 's,@BUILD_DLC_FALSE\@,\#,g' $< > $@
else
	sed -e 's,@sbindir\@,$(sbindir),g' \
	    -e 's,@sysconfdir\@,$(sysconfdir),g' \
	    -e 's,@BUILD_DLC_TRUE\@,\#,g' \
	    -e 's,@BUILD_DLC_FALSE\@,,g' $< > $@
endif
