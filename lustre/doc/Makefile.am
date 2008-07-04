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

MANFILES = lustre.7 lfs.1 mount.lustre.8 mkfs.lustre.8 tunefs.lustre.8 lctl.8 \
	llverdev.8 llbackup.8 llapi_quotactl.3

if UTILS
man_MANS = $(MANFILES)
endif

LYXFILES= $(filter-out $(patsubst %.lin,%.lyx,$(wildcard *.lin)),\
	$(wildcard *.lin *.lyx))

CLEANFILES = *.aux *.tex *.log *.pdf

EXTRA_DIST = tex2pdf $(MANFILES) $(LYXFILES)

all:

# These variables are set by lbuild/check-build.
RPMRELEASE ?= RELEASE
KERNTYPE ?= chaos
KERNRPM ?= kernel-2.4.18lustre13-RELEASE.i386.rpm

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
