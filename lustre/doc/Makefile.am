# Copyright (C) 2001  Cluster File Systems, Inc.
#
# This code is issued under the GNU General Public License.
# See the file COPYING in this distribution
LYX2PDF = lyx --export pdf
SUFFIXES = .lyx .pdf .sgml .html .txt .fig .eps

DOCS = master.pdf
# doc_DATA = $(DOCS) OBD-HOWTO.html OBD-HOWTO.txt
CLEANFILES = OBD-HOWTO.html OBD-HOWTO.txt
EXTRA_DIST = $(DOCS)

all: master.pdf

.lyx.pdf:
	$(LYX2PDF) $< 2>/dev/null || printf "\n*** Warning: not creating PDF docs; install lyx to rectify this\n"

.fig.eps:
	fig2dev -L eps $< > $@

master.pdf: master.lyx bigpicture.eps intermezzo.eps mds.eps portals-lib.eps client.eps layering.eps metadata.eps sb.eps cow.eps lockacq.eps obdfs.eps snapsetup.eps dirbodyapi.eps loraid.eps ost.eps updates.eps hotmigrate.eps lustreclusters.eps osthw.eps


dist-hook:
	rm -rf $(distdir)/figs/CVS

include $(top_srcdir)/Rules

