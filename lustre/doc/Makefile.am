# Copyright (C) 2001  Cluster File Systems, Inc.
#
# This code is issued under the GNU General Public License.
# See the file COPYING in this distribution
LYX2PDF = lyx --export pdf
LYX2TXT = lyx --export text
LYX2HTML = lyx --export html
SUFFIXES = .lyx .pdf .sgml .html .txt .fig .eps

DOCS = master.pdf lustre-HOWTO.txt
IMAGES = bigpicture.eps intermezzo.eps mds.eps portals-lib.eps client.eps layering.eps metadata.eps sb.eps cow.eps lockacq.eps obdfs.eps snapsetup.eps dirbodyapi.eps loraid.eps ost.eps updates.eps hotmigrate.eps lustreclusters.eps osthw.eps portals-lib.eps
LYXFILES = fs.lyx        llocks.lyx            master.lyx     network.lyx\
	glossary.lyx  lustre-HOWTO.lyx      mgmt.lyx       obdspec.lyx\
	intro.lyx     lustre-debugging.lyx  namespace.lyx


MAINTAINERCLEANFILES = $(IMAGES) $(DOCS)

EXTRA_DIST = $(DOCS) $(IMAGES) $(LYXFILES)

all: $(DOCS)

.lyx.pdf:
	@$(LYX2PDF) $< || printf "\n*** Warning: not creating PDF docs; install lyx to rectify this\n"

.lyx.txt:
	@$(LYX2TXT) $< || printf "\n*** Warning: not creating PDF docs; install lyx to rectify this\n"

.lyx.html:
	@$(LYX2HTML) $< || printf "\n*** Warning: not creating PDF docs; install lyx to rectify this\n"

.fig.eps:
	-fig2dev -L eps $< > $@

master.pdf: master.lyx $(IMAGES)

dist-hook:
	rm -rf $(distdir)/figs/CVS

include $(top_srcdir)/Rules
