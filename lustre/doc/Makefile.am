# Copyright (C) 2001, 2002 Cluster File Systems, Inc.
#
# This code is issued under the GNU General Public License.
# See the file COPYING in this distribution
LYX2PDF = lyx --export pdf
LYX2TXT = lyx --export text
LYX2HTML = lyx --export html
SUFFIXES = .lyx .pdf .sgml .html .txt .fig .eps

DOCS = lustre.pdf lustre-HOWTO.txt
IMAGES =  cache1.eps cache2.eps intermezzocache.eps intermezzofilesys.eps meta.eps metadata1.eps networklayer.eps bigpicture.eps intermezzo.eps mds.eps portals.eps client.eps layering.eps metadata.eps sb.eps cow.eps lockacq.eps obdfs.eps snapsetup.eps dirbodyapi.eps loraid.eps ost.eps updates.eps hotmigrate.eps lustreclusters.eps osthw.eps portals-lib.eps lockqueues.eps lockexample1.eps lockexample2.eps lockexample3.eps lockexample4.eps lockseverity.eps
LYXFILES= master.lyx evolution.lyx  llocks.lyx mgmt.lyx uncertain.lyx\
	fs.lyx         lustre-HOWTO.lyx      namespace.lyx\
	glossary.lyx   lustre-debugging.lyx  network.lyx\
	intro.lyx      obdspec.lyx recovery.lyx

MAINTAINERCLEANFILES =  $(IMAGES) $(DOCS) lustre-HOWTO.lyx
CLEANFILES = *.lyxT

EXTRA_DIST = $(DOCS) $(IMAGES) $(LYXFILES) DOCVERSION

all: $(DOCS)

# update date and version in document
tag := $(shell cat $(srcdir)/CVS/Tag 2>/dev/null || echo HEAD)
addstamp = sed "s|^Date:.*|Date: `date +%x`|g; s|^Version:.*|Version: $(tag)|g"

DOCVERSION:
	echo $(tag) > DOCVERSION

.lyx.pdf:
	rm -f $<T
	$(addstamp) $< > $<T
	@$(LYX2PDF) $< || printf "\n*** Warning: not creating PDF docs; install lyx to rectify this\n"
	rm -f $<T

.lyx.txt:
	rm -f $<T
	$(addstamp) $< > $<T
	@$(LYX2TXT) $< || printf "\n*** Warning: not creating text docs; install lyx to rectify this\n"
	rm -f $<T

.lyx.html:
	rm -f $<T
	$(addstamp) $< > $<T
	@$(LYX2HTML) $< || printf "\n*** Warning: not creating HTML docs; install lyx to rectify this\n"
	rm -f $<T

.fig.eps:
	-fig2dev -L eps $< > $@

lustre.lyx: master.lyx $(IMAGES) DOCVERSION
	(ver="`cat DOCVERSION`" ;\
	echo "version for $< is $$ver";\
	sed "s/VERSION/version $$ver/" < $< > lustre.lyx.tmp ;\
	thedate=`date +%x` ; sed "s/DATE/$$thedate, /" < lustre.lyx.tmp > lustre.lyx ;\
	)

syncweb: lustre.pdf
	cp lustre.pdf /usr/src/www/content/lustre/docs/lustre.pdf
	( cd /usr/src/www ; make lustre ; make synclustre )

dist-hook:
	rm -rf $(distdir)/figs/CVS

include $(top_srcdir)/Rules
