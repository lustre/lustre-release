SUBDIRS = obdfilter-survey sgpdd-survey ost-survey ior-survey
SUBDIRS += mds-survey stats-collect

EXTRA_DIST = lustre-iokit.spec

rpms rpm: dist
	rpmbuild -ta $(PACKAGE)-$(VERSION).tar.gz

srpm: dist
	rpmbuild -ts $(PACKAGE)-$(VERSION).tar.gz
