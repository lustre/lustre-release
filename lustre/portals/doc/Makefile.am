# Copyright (C) 2001  Cluster File Systems, Inc.
#
# This code is issued under the GNU General Public License.
# See the file COPYING in this distribution

LYX2PDF = lyx --export pdf
LYX2TXT = lyx --export text
LYX2HTML = lyx --export html
SUFFIXES = .lin .lyx .pdf .sgml .html .txt .fig .eps

DOCS = portals3.pdf 
IMAGES = file.eps flow_new.eps get.eps mpi.eps portals.eps put.eps
LYXFILES= portals3.lyx

MAINTAINERCLEANFILES =  $(IMAGES) $(DOCS) $(GENERATED)
GENERATED = 
EXTRA_DIST = $(DOCS) $(IMAGES) $(LYXFILES) 

all: $(DOCS)

# update date and version in document
date := $(shell date +%x)
tag := $(shell echo '$$Name:  $$' | sed -e 's/^\$$Na''me: *\$$$$/HEAD/; s/^\$$Na''me: \(.*\) \$$$$/\1/')
addversion = sed -e 's|@T''AG@|$(tag)|g; s|@VER''SION@|$(VERSION)|g; s|@DA''TE@|$(date)|g'

# Regenerate when the $(VERSION) or $Name:  $ changes.
.INTERMEDIATE: $(GENERATED)
$(GENERATED) : %.lyx: %.lin Makefile
	$(addversion) $< > $@

.lyx.pdf:
	@$(LYX2PDF) $< || printf "\n*** Warning: not creating PDF docs; install lyx to rectify this\n"

.lyx.txt:
	@$(LYX2TXT) $< || printf "\n*** Warning: not creating text docs; install lyx to rectify this\n"
.lyx.html:
	@$(LYX2HTML) $< || printf "\n*** Warning: not creating HTML docs; install lyx to rectify this\n"
.fig.eps:
	-fig2dev -L eps $< > $@

portals3.pdf portals3.txt portals3.html: $(IMAGES) portals3.lyx

syncweb: portals3.pdf
#	cp lustre.pdf /usr/src/www/content/lustre/docs/lustre.pdf
#	( cd /usr/src/www ; make lustre ; make synclustre )

