SRC_XML=$(wildcard *.xml)
SRC_IMG=$(wildcard figures/*.png)
SRCS=$(SRC_XML) $(SRC_IMG)

TGT_BASE=lustre_manual

RNG_LIN=/usr/share/xml/docbook/schema/rng/5.0/docbookxi.rng
RNG_MAC=/opt/local/share/xml/docbook/5.0/rng/docbookxi.rng
RNG=$(or $(shell ls $(RNG_LIN) 2> /dev/null), \
	 $(shell ls $(RNG_MAC) 2> /dev/null))
XSL_LIN=/usr/share/xml/docbook/stylesheet/docbook-xsl-ns
XSL_MAC=/opt/local/share/xsl/docbook-xsl
XSL=$(or $(shell ls -d $(XSL_LIN) 2> /dev/null), \
	 $(shell ls -d $(XSL_MAC) 2> /dev/null))

.PHONY: check
check: $(SRC_XML)
	xmllint --noout --xinclude --noent --relaxng $(RNG) ./index.xml

# Note: can't use "suffix" instead of "subst", because it keeps the '.'
$(TGT_BASE).html $(TGT_BASE).fo: $(SRCS)
	xsltproc --stringparam fop1.extensions  1 \
		--stringparam section.label.includes.component.label 1 \
		--stringparam section.autolabel 1 \
		--stringparam chapter.autolabel 1 \
		--stringparam appendix.autolabel 1 \
		--xinclude -o $@ $(XSL)/$(subst $(TGT_BASE).,,$@)/docbook.xsl ./index.xml

$(TGT_BASE).pdf: $(TGT_BASE).fo
		fop $< $@

.PHONY: html
html: $(TGT_BASE).html

.PHONY: pdf
pdf: $(TGT_BASE).pdf

.PHONY: push
push:
	git push ssh://review.whamcloud.com:29418/doc/manual HEAD:refs/for/master
