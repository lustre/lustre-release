# Copyright (C) 2001, 2002 Cluster File Systems, Inc.
#
# This code is issued under the GNU General Public License.
# See the file COPYING in this distribution
LYX2PDF = lyx --export pdf
LYX2PS = lyx --export ps
LYX2TEX = lyx --export latex
LYX2TXT = lyx --export text
LYX2HTML = lyx --export html
LATEX = latex
DVIPS = dvips
PS2PDF = ps2pdf
TEXEXPAND = texexpand
SUFFIXES = .lin .lyx .pdf .ps .sgml .html .txt .tex .fig .eps .dvi

DOCS = lustre.pdf lustre-HOWTO.txt
IMAGES =  sys_open.eps sys_write.eps sys_mount.eps cache1.eps cache2.eps intermezzocache.eps intermezzofilesys.eps meta.eps metadata1.eps networklayer.eps bigpicture.eps intermezzo.eps mds.eps portals.eps client.eps layering.eps metadata.eps sb.eps cow.eps lockacq.eps obdfs.eps snapsetup.eps dirbodyapi.eps loraid.eps ost.eps updates.eps hotmigrate.eps lustreclusters.eps osthw.eps portals-lib.eps lockqueues.eps lockexample1.eps lockexample2.eps lockexample3.eps lockexample4.eps lockseverity.eps gssapi.eps lovextents.eps cpsd.eps setup-accept.eps authenticate.eps login.eps
LYXFILES= lustre.lin evolution.lyx  llocks.lyx mgmt.lyx uncertain.lyx\
	fs.lyx         lustre-HOWTO.lin      namespace.lyx\
	glossary.lyx   lustre-debugging.lyx  network.lyx\
	intro.lyx      obdspec.lyx recovery.lyx

MAINTAINERCLEANFILES =  $(IMAGES) $(DOCS) $(VERSIONED)
CLEANFILES = *.aux *.tex doc.old/*.aux doc.old/*.tex *.eps
VERSIONED = lustre-HOWTO.lyx lustre.lyx doc.old/lustre-HOWTO.lyx doc.old/lustre.lyx
GENERATED = $(VERSIONED) lustre-full.tex lustre-chbar.tex

EXTRA_DIST = chbar.sh postbar $(DOCS) $(IMAGES) $(LYXFILES) lustre.bib

all: $(DOCS)

# These variables are set by lbuild/check-build.
RPMRELEASE ?= RELEASE
KERNTYPE ?= chaos
KERNRPM ?= kernel-2.4.18lustre13-RELEASE.i386.rpm

# update date and version in document
date := $(shell date +%x)
tag := $(shell echo '$$Name:  $$' | sed -e 's/^\$$Na''me: *\$$$$/HEAD/; s/^\$$Na''me: \(.*\) \$$$$/\1/')
addversion = sed -e 's|@T''AG@|$(tag)|g; s|@VER''SION@|$(VERSION)|g; s|@DA''TE@|$(date)|g; s|@RPM''RELEASE@|$(RPMRELEASE)|g; s|@KERN''TYPE@|$(KERNTYPE)|g; s|@KERN''RPM@|$(KERNRPM)|g'

# Regenerate when the $(VERSION) or $Name:  $ changes.
.INTERMEDIATE: $(GENERATED)
$(VERSIONED) : %.lyx: %.lin Makefile
	$(addversion) $< > $@

.lyx.pdf:
	@echo $(LYX2PDF) $< && $(LYX2PDF) $< || printf "\n*** Warning: not creating PDF docs; install lyx to rectify this\n"

.lyx.ps:
	@echo $(LYX2PS) $< && $(LYX2PS) $< || printf "\n*** Warning: not creating PostScript docs; install lyx to rectify this\n"

.lyx.tex:
	@echo $(LYX2TEX) $< && $(LYX2TEX) $< || printf "\n*** Warning: not creating LaTeX docs; install lyx to rectify this\n"

.lyx.txt:
	@echo $(LYX2TXT) $< && $(LYX2TXT) $< || printf "\n*** Warning: not creating text docs; install lyx to rectify this\n"

.lyx.html:
	@echo $(LYX2HTML) $< && $(LYX2HTML) $< || printf "\n*** Warning: not creating HTML docs; install lyx to rectify this\n"

.tex.dvi:
	$(LATEX) $<
	$(LATEX) $<

.dvi.ps:
	$(DVIPS) $< -o $@

.ps.pdf:
	$(PS2PDF) $< $@

lustre.tex lustre.pdf lustre.txt lustre.html: $(IMAGES) lustre-HOWTO.lyx
.fig.eps:
	-fig2dev -L eps $< > $@

syncweb: lustre.pdf
	cp lustre.pdf /usr/src/www/content/lustre/docs/lustre.pdf
	( cd /usr/src/www ; make lustre ; make synclustre )
.PHONY: syncweb chbar

# Build a changebar document from the files in doc.old and this directory.
chbar: lustre-chbar.pdf

%-chbar.tex: chbar.sh postbar doc.old/%-full.tex %-full.tex
	$(SHELL) $(srcdir)/chbar.sh doc.old/$*-full.tex $*-full.tex | $(srcdir)/postbar > $@

%-full.tex: %.tex
	$(TEXEXPAND) -texinputs=. -texinputs=$(srcdir) -output=$@ $<

doc.old/lustre.tex: doc.old/lustre-HOWTO.lyx
doc.old/%-full.tex: doc.old/%.tex
	cd doc.old && $(TEXEXPAND) -texinputs=. -output=$*-full.tex $*.tex

# Check out the old directory if it doesn't exist.
doc.old/lustre.lin doc.old/lustre-HOWTO.lin:
	@if test "X$(OLD)" = X; then \
	  echo "You must populate doc.old or specify a CVS tag like OLD=v0_5_1"; \
	  exit 1; \
	fi
	rm -rf doc.old
	mkdir doc.old
	cvs checkout -r $(OLD) -d doc.old lustre/doc

dist-hook:
	rm -rf $(distdir)/figs/CVS

include $(top_srcdir)/Rules
