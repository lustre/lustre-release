# Copyright (C) 2001  Cluster File Systems, Inc.
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
	intro.lyx      obdspec.lyx

MAINTAINERCLEANFILES =  $(IMAGES) $(DOCS)

EXTRA_DIST = $(DOCS) $(IMAGES) $(LYXFILES)

all: $(DOCS)

# update date and version in document
.lyx.pdf:
	@$(LYX2PDF) $< || printf "\n*** Warning: not creating PDF docs; install lyx to rectify this\n"

.lyx.txt:
	@$(LYX2TXT) $< || printf "\n*** Warning: not creating PDF docs; install lyx to rectify this\n"

.lyx.html:
	@$(LYX2HTML) $< || printf "\n*** Warning: not creating PDF docs; install lyx to rectify this\n"

.fig.eps:
	-fig2dev -L eps $< > $@

lustre.lyx: master.lyx $(IMAGES)
	(ver=`awk -F/ -v key=$<  '$$2 == key {print $$3}' CVS/Entries`;\
	echo "version for $< is $$ver";\
	sed "s/version .*/version $$ver/" < $< > lustre.lyx;\
	)

syncweb: lustre.pdf
	cp lustre.pdf /usr/src/www/content/lustre/docs/lustre.pdf
	( cd /usr/src/www ; make lustre ; make synclustre )

dist-hook:
	rm -rf $(distdir)/figs/CVS

include $(top_srcdir)/Rules
