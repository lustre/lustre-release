# SPDX-License-Identifier: GPL-2.0

#
# This file is part of Lustre, http://www.lustre.org/
#
# docs/manual/Makefile.am
#
# Automake file for building the Lustre Operations Manual
#

AUTOMAKE_OPTIONS = foreign

# Source files
SRC_XML = $(wildcard $(srcdir)/*.xml)
SRC_IMG = $(wildcard $(srcdir)/figures/*.png)
SRCS = $(SRC_XML) $(SRC_IMG)

# Output base name
TGT_BASE = lustre_manual

# Build output directory
BUILDDIR = $(builddir)/build

# DocBook paths (set by configure)
RNG = @DOCBOOK_RNG@
XSL = @DOCBOOK_XSL@

# XSL stylesheets for different output formats
PRIMARYXSL_HTML = $(XSL)/html/docbook.xsl
PRIMARYXSL_XHTML = $(XSL)/xhtml/docbook.xsl
PRIMARYXSL_FO = $(XSL)/fo/docbook.xsl
PRIMARYXSL_CHUNK = $(XSL)/html/chunkfast.xsl

# Chunked HTML output directory
CHUNKED_HTML = $(BUILDDIR)/chunked-html

# Markdown output directory
MARKDOWN_DIR = $(BUILDDIR)/markdown

.PHONY: all clean check html xhtml pdf chunked-html markdown

all: check xhtml html pdf chunked-html markdown

# Create build directory
$(BUILDDIR):
	$(MKDIR_P) $(BUILDDIR)

# Validate XML
check: $(SRC_XML)
	@echo "Validating DocBook XML..."
	$(XMLLINT) --noout --xinclude --noent --relaxng $(RNG) $(srcdir)/index.xml

# Single-page HTML output
$(BUILDDIR)/$(TGT_BASE).html: $(SRCS) | $(BUILDDIR)
	@echo "Building single-page HTML..."
	sed -e 's;PRIMARYXSL;$(PRIMARYXSL_HTML);' $(srcdir)/style/customstyle.xsl | \
	$(XSLTPROC) --xinclude -o $@ - $(srcdir)/index.xml

html: $(BUILDDIR)/$(TGT_BASE).html

# Single-page XHTML output
$(BUILDDIR)/$(TGT_BASE).xhtml: $(SRCS) | $(BUILDDIR)
	@echo "Building single-page XHTML..."
	sed -e 's;PRIMARYXSL;$(PRIMARYXSL_XHTML);' $(srcdir)/style/customstyle.xsl | \
	$(XSLTPROC) --xinclude -o $@ - $(srcdir)/index.xml

xhtml: $(BUILDDIR)/$(TGT_BASE).xhtml

# FO output (intermediate for PDF)
$(BUILDDIR)/$(TGT_BASE).fo: $(SRCS) | $(BUILDDIR)
	@echo "Building FO intermediate..."
	sed -e 's;PRIMARYXSL;$(PRIMARYXSL_FO);' $(srcdir)/style/customstyle_fo.xsl | \
	$(XSLTPROC) --xinclude -o $@ - $(srcdir)/index.xml

# PDF output
$(BUILDDIR)/$(TGT_BASE).pdf: $(BUILDDIR)/$(TGT_BASE).fo
	@echo "Building PDF..."
	$(FOP) $< $@

pdf: $(BUILDDIR)/$(TGT_BASE).pdf

# Chunked HTML output
$(CHUNKED_HTML)/index.html: $(SRCS) | $(BUILDDIR)
	@echo "Building chunked HTML..."
	$(MKDIR_P) $(CHUNKED_HTML)
	sed -e 's;PRIMARYXSL;$(PRIMARYXSL_CHUNK);' $(srcdir)/style/customstyle.xsl | \
	$(XSLTPROC) --xinclude -o $(CHUNKED_HTML)/ - $(srcdir)/index.xml
	cp -r $(srcdir)/figures $(CHUNKED_HTML)/

chunked-html: $(CHUNKED_HTML)/index.html

# Markdown output (for AI consumption)
markdown: | $(BUILDDIR)
	@echo "Building Markdown..."
	$(MKDIR_P) $(MARKDOWN_DIR)
	@for xml in $(srcdir)/*.xml; do \
		base=$$(basename $$xml .xml); \
		case "$$base" in \
			index|ix|Revision|I_*|II_*|III_*|IV_*|V_*|VI_*|legalnotice*) \
				continue ;; \
		esac; \
		echo "  Converting $$base.xml..."; \
		$(PANDOC) -f docbook -t markdown -o $(MARKDOWN_DIR)/$$base.md $$xml; \
	done
	@echo "Markdown conversion complete."

# Clean build outputs
clean-local:
	rm -rf $(BUILDDIR)

# Extra files to distribute
EXTRA_DIST = $(SRC_XML) $(SRC_IMG) \
	style \
	tools \
	webhelp \
	figures \
	Makefile \
	.gitignore \
	README.md
