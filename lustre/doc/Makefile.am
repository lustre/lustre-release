# Copyright (C) 2001, 2002 Cluster File Systems, Inc.
#
# This code is issued under the GNU General Public License.
# See the file COPYING in this distribution
LYX2PDF = GS_OPTIONS=-dCompatibilityLevel=1.1 $(srcdir)/tex2pdf -overwrite
TEX2PDF = GS_OPTIONS=-dCompatibilityLevel=1.1 $(srcdir)/tex2pdf -overwrite
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
HOWTODOC = lustre-HOWTO.txt
IMAGES := $(patsubst %.fig,%.eps,$(wildcard *.fig))
LYXFILES= $(filter-out $(patsubst %.lin,%.lyx,$(wildcard *.lin)),\
	$(wildcard *.lin *.lyx))

MAINTAINERCLEANFILES =  $(IMAGES) $(DOCS) $(VERSIONED)
CLEANFILES = *.aux *.tex doc.old/*.aux doc.old/*.tex *.eps *.log *.pdf
VERSIONED = lustre-HOWTO.lyx lustre.lyx doc.old/lustre-HOWTO.lyx doc.old/lustre.lyx
GENERATED = $(VERSIONED) lustre-full.tex lustre-chbar.tex

EXTRA_DIST = chbar.sh postbar tex2pdf $(DOCS) $(IMAGES) $(LYXFILES) lustre.bib

all: $(HOWTODOC)
docs: $(DOCS)

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

.tex.pdf:
	$(TEX2PDF) $<

.tex.dvi:
	$(LATEX) $<
	$(LATEX) $<

.dvi.ps:
	$(DVIPS) $< -o $@

.ps.pdf:
	$(PS2PDF) $< $@

lustre.tex lustre.pdf lustre.txt lustre.html: $(IMAGES) $(LYXFILES) lustre-HOWTO.lyx
.fig.eps:
	-fig2dev -L eps $< > $@

syncweb: lustre.pdf
	cp lustre.pdf /usr/src/www/content/lustre/docs/lustre.pdf
	( cd /usr/src/www ; make lustre ; make synclustre )
.PHONY: syncweb chbar

# Build a changebar document from the files in doc.old and this directory.
chbar: lustre-chbar.pdf

# FIXME: Temporary rules until pdftex displays changebars correctly.
lustre-chbar.pdf: lustre-chbar-nopdf.ps
	$(PS2PDF) $< $@
lustre-chbar-nopdf.ps: lustre-chbar-nopdf.dvi
	$(DVIPS) $< -o $@
lustre-chbar-nopdf.dvi: lustre-chbar-nopdf.tex
	$(LATEX) $<
	$(LATEX) $<
lustre-chbar-nopdf.tex: lustre-chbar.tex
	sed -e 's/^\(.*usepackage.*pdftex\)/%\1/' $< > $@

%-chbar.tex: chbar.sh postbar doc.old/%-full.tex %-full.tex
	$(SHELL) $(srcdir)/chbar.sh doc.old/$*-full.tex $*-full.tex | $(srcdir)/postbar > $@

# This rule needs to come before the next %-full.tex rule.
doc.old/lustre.tex: doc.old/lustre-HOWTO.lyx
doc.old/%-full.tex: doc.old/%.tex
	cd doc.old && $(TEXEXPAND) -texinputs=. -output=$*-full.tex $*.tex

# This rule needs to come after the more specific doc.old rule.
%-full.tex: %.tex
	$(TEXEXPAND) -texinputs=. -texinputs=$(srcdir) -output=$@ $<

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
