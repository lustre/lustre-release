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

<xsl:param name="chapter.autolabel" select="1"></xsl:param>
<xsl:param name="section.autolabel" select="1"></xsl:param>
<xsl:param name="appendix.autolabel" select="1"></xsl:param>
<xsl:param name="autotoc.label.in.hyperlink" select="1"></xsl:param>
<xsl:param name="section.label.includes.component.label" select="1"></xsl:param>

<!--  textdecoration_1 applies the style to the text to highlight an region
		of the documentation refers to a lustre specific version.

		template_{1,2,3} all use the 'condition="{l23,l24}" attributes and add
		decoration to the rendered version of the manual to show lustre version
		specific features. -->

<!-- textdecoration_1: a template to highlight regions of text. -->
<xsl:template name='textdecoration_1'>
	<xsl:param name='version'/>
	<xsl:param name='chunkid'/>
	<fo:block-container id="{$chunkid}"
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
			<xsl:apply-templates/>
		</fo:block>
	</fo:block-container>
</xsl:template>

<!-- conditional matching template: this calls text decoration
          template with the correct variables. -->
<xsl:template match="*[@condition]">
    <xsl:variable name="id">
        <xsl:call-template name="object.id"/>
    </xsl:variable>
    <xsl:call-template name='section.titlepage'/>
    <xsl:choose>
        <xsl:when test="@condition = 'l21'">
            <xsl:call-template name='textdecoration_1'>
                <xsl:with-param name='version' select="'introduced in Lustre 2.1'"/>
                <xsl:with-param name='chunkid' select="$id"/>
            </xsl:call-template>
        </xsl:when>
        <xsl:when test="@condition = 'l22'">
            <xsl:call-template name='textdecoration_1'>
                <xsl:with-param name='version' select="'introduced in Lustre 2.2'"/>
                <xsl:with-param name='chunkid' select="$id"/>
            </xsl:call-template>
        </xsl:when>
        <xsl:when test="@condition = 'l23'">
            <xsl:call-template name='textdecoration_1'>
                <xsl:with-param name='version' select="'introduced in Lustre 2.3'"/>
                <xsl:with-param name='chunkid' select="$id"/>
            </xsl:call-template>
        </xsl:when>
        <xsl:when test="@condition = 'l24'">
            <xsl:call-template name='textdecoration_1'>
                <xsl:with-param name='version' select="'introduced in Lustre 2.4'"/>
                <xsl:with-param name='chunkid' select="$id"/>
            </xsl:call-template>
        </xsl:when>
        <xsl:when test="@condition = 'l25'">
            <xsl:call-template name='textdecoration_1'>
                <xsl:with-param name='version' select="'introduced in Lustre 2.5'"/>
                <xsl:with-param name='chunkid' select="$id"/>
            </xsl:call-template>
        </xsl:when>
        <xsl:otherwise>
            <xsl:call-template name='textdecoration_1'>
                <xsl:with-param name='version' select="'unrecognised Lustre version'"/>
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
			<xsl:when test="@condition='l21'">L 2.1</xsl:when>
			<xsl:when test="@condition='l22'">L 2.2</xsl:when>
			<xsl:when test="@condition='l23'">L 2.3</xsl:when>
			<xsl:when test="@condition='l24'">L 2.4</xsl:when>
			<xsl:when test="@condition='l25'">L 2.5</xsl:when>
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
