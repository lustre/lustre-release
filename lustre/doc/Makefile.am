# Copyright (C) 2001  Cluster File Systems, Inc.
#
# This code is issued under the GNU General Public License.
# See the file COPYING in this distribution

DOCS = OBD-HOWTO.sgml OLVM.txt figs notes.txt obdtrace_demo.txt
doc_DATA = $(DOCS) OBD-HOWTO.html OBD-HOWTO.txt
CLEANFILES = OBD-HOWTO.html OBD-HOWTO.txt
EXTRA_DIST = $(DOCS)

.sgml.html:
	sgml2html -split 0 $<

.sgml.txt:
	sgml2txt $<

SUFFIXES = .sgml .html .txt

dist-hook:
	rm -rf $(distdir)/figs/CVS

include $(top_srcdir)/Rules

