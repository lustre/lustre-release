<?xml version='1.0'?>
<xsl:stylesheet  xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
	xmlns:fo="http://www.w3.org/1999/XSL/Format"
	xmlns:d="http://docbook.org/ns/docbook"
	exclude-result-prefixes="d"
	version="1.0" >
<!-- xsl:import takes place at compile time. For this reason, I sed in the correct
     primary xsl pdf, and then run xsltproc -->
<xsl:import href="PRIMARYXSL"/>
<xsl:output method='xml'/>

<xsl:param name="fop1.extensions" select="1"></xsl:param>
<xsl:param name="chapter.autolabel" select="1"></xsl:param>
<xsl:param name="section.autolabel" select="1"></xsl:param>
<xsl:param name="appendix.autolabel" select="1"></xsl:param>
<xsl:param name="autotoc.label.in.hyperlink" select="1"></xsl:param>
<xsl:param name="section.label.includes.component.label" select="1"></xsl:param>

<!-- TODO: ideally generalize customstyle_common.xsl suffeciently
     so that is can be included in this file. Currently, this file
	 duplicates customerstyle_common.xsl with some minor differences. -->

<!-- textdecoration_1: a template to highlight regions of text.-->
<xsl:template name='textdecoration_1'>
	<xsl:param name='version'/>
	<xsl:param name='content'/>
	<xsl:param name='id'/>
	<fo:block id="{id}">
	<fo:block-container
		padding='5pt'
		border-color='gray'
		border-style='solid'
		border-width='1pt'>
		<fo:block-container float='left' text-indent='3px' start-indent='-20px'>
			<fo:block background-color="gray">
				<xsl:value-of select='$version'/>
			</fo:block>
		</fo:block-container>
		<fo:block text-indent='0px' start-indent='0px'>
			<xsl:copy-of select="$content"/>
		</fo:block>
		</fo:block-container>
	</fo:block>
</xsl:template>

<!-- mychapter definition This has been copied from xsl-ns-stylesheets/fo/component.xsl 
	and modified to provide highlight regions of text for an entire chapter. 
	This is consistent with the high-lighting provided by textdecoration_1 !-->
<xsl:template name="mychapter">
	<xsl:param name='version'/>
	<xsl:param name='chunkid'/>
  <xsl:variable name="id">
    <xsl:call-template name="object.id"/>
  </xsl:variable>

  <xsl:variable name="master-reference">
    <xsl:call-template name="select.pagemaster"/>
  </xsl:variable>

  <fo:page-sequence hyphenate="{$hyphenate}"
                    master-reference="{$master-reference}">
    <xsl:attribute name="language">
      <xsl:call-template name="l10n.language"/>
    </xsl:attribute>
    <xsl:attribute name="format">
      <xsl:call-template name="page.number.format">
        <xsl:with-param name="master-reference" select="$master-reference"/>
      </xsl:call-template>
    </xsl:attribute>
    <xsl:attribute name="initial-page-number">
      <xsl:call-template name="initial.page.number">
        <xsl:with-param name="master-reference" select="$master-reference"/>
      </xsl:call-template>
    </xsl:attribute>

    <xsl:attribute name="force-page-count">
      <xsl:call-template name="force.page.count">
        <xsl:with-param name="master-reference" select="$master-reference"/>
      </xsl:call-template>
    </xsl:attribute>

    <xsl:attribute name="hyphenation-character">
      <xsl:call-template name="gentext">
        <xsl:with-param name="key" select="'hyphenation-character'"/>
      </xsl:call-template>
    </xsl:attribute>
    <xsl:attribute name="hyphenation-push-character-count">
      <xsl:call-template name="gentext">
        <xsl:with-param name="key" select="'hyphenation-push-character-count'"/>
      </xsl:call-template>
    </xsl:attribute>
    <xsl:attribute name="hyphenation-remain-character-count">
      <xsl:call-template name="gentext">
        <xsl:with-param name="key" select="'hyphenation-remain-character-count'"/>
      </xsl:call-template>
    </xsl:attribute>

    <xsl:apply-templates select="." mode="running.head.mode">
      <xsl:with-param name="master-reference" select="$master-reference"/>
    </xsl:apply-templates>

    <xsl:apply-templates select="." mode="running.foot.mode">
      <xsl:with-param name="master-reference" select="$master-reference"/>
    </xsl:apply-templates>

    <fo:flow flow-name="xsl-region-body">
      <xsl:call-template name="set.flow.properties">
        <xsl:with-param name="element" select="local-name(.)"/>
        <xsl:with-param name="master-reference" select="$master-reference"/>
      </xsl:call-template>

	<fo:block-container id='chapterdecoration-{$chunkid}'
			padding='5pt'
			border-color='gray'
			border-style='solid'
			border-width='1pt'>
			<fo:block-container float='left' text-indent='3px' start-indent='-20px'>
				<fo:block background-color="gray">
					<xsl:value-of select='$version'/>
				</fo:block>
			</fo:block-container>
		  <fo:block id="{$id}"
					xsl:use-attribute-sets="component.titlepage.properties">
			<xsl:call-template name="chapter.titlepage"/>
		  </fo:block>

		  <!-- RHEL and SLES versions have an older docbook xsl install
		       that fails on this call: 
			   xsl:call-template name="make.component.tocs"/-->

		  <xsl:apply-templates/>
      </fo:block-container>
    </fo:flow>
  </fo:page-sequence>
</xsl:template>


<!-- conditional matching template: this calls text decoration
          template with the correct variables. -->
<xsl:template match="*[@condition]">
        <xsl:param name="content">
                <xsl:apply-imports/>
        </xsl:param>
    <xsl:variable name="id">
        <xsl:call-template name="object.id"/>
    </xsl:variable>
	<xsl:variable name="versionstr">
		<xsl:choose>
			<xsl:when test="@condition = 'l23'">Introduced in Lustre 2.3</xsl:when>
			<xsl:when test="@condition = 'l24'">Introduced in Lustre 2.4</xsl:when>
			<xsl:when test="@condition = 'l25'">Introduced in Lustre 2.5</xsl:when>
			<xsl:when test="@condition = 'l26'">Introduced in Lustre 2.6</xsl:when>
			<xsl:when test="@condition = 'l27'">Introduced in Lustre 2.7</xsl:when>
			<xsl:when test="@condition = 'l28'">Introduced in Lustre 2.8</xsl:when>
			<xsl:when test="@condition = 'l29'">Introduced in Lustre 2.9</xsl:when>
			<xsl:when test="@condition = 'l2A'">Introduced in Lustre 2.10</xsl:when>
			<xsl:when test="@condition = 'l2B'">Introduced in Lustre 2.11</xsl:when>
			<xsl:when test="@condition = 'l2C'">Introduced in Lustre 2.12</xsl:when>
			<xsl:otherwise>Documentation Error: unrecognised condition attribute</xsl:otherwise>
		</xsl:choose>
	</xsl:variable>
    <xsl:choose>
        <xsl:when test="name(..) = 'part'">
    		<xsl:call-template name='mychapter'>
                <xsl:with-param name='version' select="$versionstr"/>
                <xsl:with-param name='chunkid' select="$id"/>
            </xsl:call-template>
		</xsl:when>
		<xsl:otherwise>
            <xsl:call-template name='textdecoration_1'>
                <xsl:with-param name='version' select="$versionstr"/>
				<xsl:with-param name='content' select="$content"/>
                <xsl:with-param name='chunkid' select="$id"/>
            </xsl:call-template>
		</xsl:otherwise>
    </xsl:choose>
</xsl:template>

<!-- toc.line template: This template over loads the behavior of creating the table of contents. It
		adds in a small entry to identify lustre version specific features.
		for more information, see this page:
		http://xml.web.cern.ch/XML/www.sagehill.net/xml/docbookxsl/PrintCustomEx.html#PrintTocEntries -->
<xsl:template name="toc.line">
	<xsl:variable name="id">
		<xsl:call-template name="object.id"/>
	</xsl:variable>
	<xsl:variable name="lustrecond">
		<xsl:choose>
			<xsl:when test="@condition='l23'">L 2.3</xsl:when>
			<xsl:when test="@condition='l24'">L 2.4</xsl:when>
			<xsl:when test="@condition='l25'">L 2.5</xsl:when>
			<xsl:when test="@condition='l26'">L 2.6</xsl:when>
			<xsl:when test="@condition='l27'">L 2.7</xsl:when>
			<xsl:when test="@condition='l28'">L 2.8</xsl:when>
			<xsl:when test="@condition='l29'">L 2.9</xsl:when>
			<xsl:when test="@condition='l2A'">L 2.10</xsl:when>
			<xsl:when test="@condition='l2B'">L 2.11</xsl:when>
			<xsl:when test="@condition='l2C'">L 2.12</xsl:when>
			<xsl:otherwise></xsl:otherwise>
		</xsl:choose>
	</xsl:variable>

	<xsl:variable name="label">
		<xsl:apply-templates select="." mode="label.markup"/>
	</xsl:variable>
	<fo:block text-align-last="justify"
			end-indent="{$toc.indent.width}pt"
			last-line-end-indent="-{$toc.indent.width}pt">
		<fo:inline keep-with-next.within-line="always">
			<xsl:choose>
				<xsl:when test="local-name(.) = 'chapter'">
					<xsl:attribute name="font-weight">bold</xsl:attribute>
				</xsl:when>
			</xsl:choose>
			<fo:basic-link internal-destination="{$id}">
				<xsl:if test="$label != ''">
					<xsl:copy-of select="$label"/>
					<xsl:value-of select="$autotoc.label.separator"/>
				</xsl:if>
				<xsl:apply-templates select="." mode="title.markup"/>
			</fo:basic-link>
		</fo:inline>
		<fo:inline keep-together.within-line="always">
			<xsl:text> </xsl:text>
			<fo:leader leader-pattern="dots"
					leader-pattern-width="3pt"
					leader-alignment="reference-area"
					keep-with-next.within-line="always"/>
			<xsl:text>  </xsl:text>
			<xsl:value-of select='$lustrecond'/>
			<xsl:text>  </xsl:text>
			<fo:basic-link internal-destination="{$id}">
				<fo:page-number-citation ref-id="{$id}"/>
			</fo:basic-link>
		</fo:inline>
	</fo:block>
</xsl:template>

</xsl:stylesheet>
