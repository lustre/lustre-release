#
# GPL HEADER START
#
# DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 only,
# as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License version 2 for more details (a copy is included
# in the LICENSE file that accompanied this code).
#
# You should have received a copy of the GNU General Public License
# version 2 along with this program; If not, see
# http://www.gnu.org/licenses/gpl-2.0.html
#
# GPL HEADER END
#

#
# Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
# Use is subject to license terms.
#

#
# This file is part of Lustre, http://www.lustre.org/
#

LYX2PDF = lyx --export pdf
LYX2TXT = lyx --export text
LYX2HTML = lyx --export html
SUFFIXES = .lin .lyx .pdf .sgml .html .txt .fig .eps

if DOC
  DOCS = portals3.pdf
else
  DOCS =
endif

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
