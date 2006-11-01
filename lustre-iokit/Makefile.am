SUBDIRS = obdfilter-survey sgpdd-survey ost-survey ior-survey

EXTRA_DIST = lustre-iokit.spec

rpm: dist
	rpmbuild -ta $(PACKAGE)-$(VERSION).tar.gz
