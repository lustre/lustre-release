# Copyright (C) 2001, 2002 Cluster File Systems, Inc.
#
# This code is issued under the GNU General Public License.
# See the file COPYING in this distribution
LYX2PDF = lyx --export pdf
LYX2TXT = lyx --export text
LYX2HTML = lyx --export html
SUFFIXES = .lin .lyx .pdf .sgml .html .txt .fig .eps

DOCS = lustre.pdf lustre-HOWTO.txt
IMAGES =  cache1.eps cache2.eps intermezzocache.eps intermezzofilesys.eps meta.eps metadata1.eps networklayer.eps bigpicture.eps intermezzo.eps mds.eps portals.eps client.eps layering.eps metadata.eps sb.eps cow.eps lockacq.eps obdfs.eps snapsetup.eps dirbodyapi.eps loraid.eps ost.eps updates.eps hotmigrate.eps lustreclusters.eps osthw.eps portals-lib.eps lockqueues.eps lockexample1.eps lockexample2.eps lockexample3.eps lockexample4.eps lockseverity.eps
LYXFILES= lustre.lin evolution.lyx  llocks.lyx mgmt.lyx uncertain.lyx\
	fs.lyx         lustre-HOWTO.lin      namespace.lyx\
	glossary.lyx   lustre-debugging.lyx  network.lyx\
	intro.lyx      obdspec.lyx recovery.lyx

MAINTAINERCLEANFILES =  $(IMAGES) $(DOCS) $(GENERATED)
GENERATED = lustre-HOWTO.lyx lustre.lyx

EXTRA_DIST = $(DOCS) $(IMAGES) $(LYXFILES) master.bib

all: $(DOCS)

# update date and version in document
tag := $(shell sed -e 's/^.//' $(srcdir)/CVS/Tag)
date := $(shell date +%x)
addversion = sed -e 's|@T''AG@|$(tag)|g; s|@VER''SION@|$(VERSION)|g; s|@DA''TE@|$(date)|g'

# Regenerate when the $(VERSION) or CVS/Tag changes.
CVS/Tag:
	echo NHEAD > CVS/Tag
.INTERMEDIATE: $(GENERATED)
$(GENERATED) : %.lyx: %.lin Makefile CVS/Tag
	$(addversion) $< > $@

.lyx.pdf:
	@$(LYX2PDF) $< || printf "\n*** Warning: not creating PDF docs; install lyx to rectify this\n"

.lyx.txt:
	@$(LYX2TXT) $< || printf "\n*** Warning: not creating text docs; install lyx to rectify this\n"

.lyx.html:
	@$(LYX2HTML) $< || printf "\n*** Warning: not creating HTML docs; install lyx to rectify this\n"

lustre.pdf: $(IMAGES)
.fig.eps:
	-fig2dev -L eps $< > $@

syncweb: lustre.pdf
	cp lustre.pdf /usr/src/www/content/lustre/docs/lustre.pdf
	( cd /usr/src/www ; make lustre ; make synclustre )

dist-hook:
	rm -rf $(distdir)/figs/CVS

include $(top_srcdir)/Rules
