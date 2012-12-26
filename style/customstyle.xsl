<?xml version='1.0'?>
<xsl:stylesheet  xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns="http://www.w3.org/1999/xhtml" version="1.0">

<!-- xsl:import takes place at compile time. For this reason, I sed in the correct
		primary xsl (for html,xhtml), and then run xsltproc -->
<xsl:import href="PRIMARYXSL"/>

<xsl:param name="html.stylesheet" select="'./style/manual.css'"/>

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

<!-- textdecoration_1: a template to apply a div with a class
		around the relevant sections of text. -->
<xsl:template name='textdecoration_1'>
	<xsl:param name='version'/>
	<xsl:param name='chunkid'/>
	<div class='versioncontent'>
		<span class='versionlabel'>
			<xsl:value-of select='$version'/>
		</span>
		<xsl:apply-templates/>
	</div>
</xsl:template>

<!-- template_1: this tempate matches condition='l23' and calls
		the textdecoration_1 template with the relevant class. -->
<xsl:template match="*[@condition='l23']">
	<xsl:variable name="id">
		<xsl:call-template name="object.id"/>
	</xsl:variable>
	<xsl:call-template name='section.titlepage'/>
	<xsl:call-template name='textdecoration_1'>
		<xsl:with-param name='version' select="'introduced in Lustre 2.3'"/>
		<xsl:with-param name='chunkid' select="$id"/>
	</xsl:call-template>
</xsl:template>

<!-- template_2: this tempate matches condition='l24' and calls
		the textdecoration_1 template with the relevant class. -->
<xsl:template match="*[@condition='l24']">
	<xsl:variable name="id">
		<xsl:call-template name="object.id"/>
	</xsl:variable>
	<xsl:call-template name='section.titlepage'/>
	<xsl:call-template name='textdecoration_1'>
		<xsl:with-param name='version' select="'introduced in Lustre 2.4'"/>
		<xsl:with-param name='chunkid' select="$id"/>
	</xsl:call-template>
</xsl:template>


<!-- template_3: This template over loads the behavior of creating the table of contents. It
		adds in a small entry to identify lustre version specific features.
		for more information, see this page:
		http://xml.web.cern.ch/XML/www.sagehill.net/xml/docbookxsl/PrintCustomEx.html#PrintTocEntries -->
<xsl:template name="toc.line">
	<xsl:param name="toc-context" select="."/>
	<xsl:param name="depth" select="1"/>
	<xsl:param name="depth.from.context" select="8"/>

	<span>
	<xsl:attribute name="class">
		<xsl:value-of select="local-name(.)"/>
	</xsl:attribute>

	<!-- * if $autotoc.label.in.hyperlink is zero, then output the label -->
	<!-- * before the hyperlinked title (as the DSSSL stylesheet does) -->
	<xsl:if test="$autotoc.label.in.hyperlink = 0">
		<xsl:variable name="label">
			<xsl:apply-templates select="." mode="label.markup"/>
		</xsl:variable>
		<xsl:copy-of select="$label"/>
		<xsl:if test="$label != ''">
			<xsl:value-of select="$autotoc.label.separator"/>
		</xsl:if>
	</xsl:if>

	<a>
		<xsl:attribute name="href">
			<xsl:call-template name="href.target">
				<xsl:with-param name="context" select="$toc-context"/>
				<xsl:with-param name="toc-context" select="$toc-context"/>
			</xsl:call-template>
		</xsl:attribute>

	<!-- * if $autotoc.label.in.hyperlink is non-zero, then output the label
			 as part of the hyperlinked title -->
		<xsl:if test="not($autotoc.label.in.hyperlink = 0)">
			<xsl:variable name="label">
				<xsl:apply-templates select="." mode="label.markup"/>
			</xsl:variable>
			<xsl:copy-of select="$label"/>
			<xsl:if test="$label != ''">
				<xsl:value-of select="$autotoc.label.separator"/>
			</xsl:if>
		</xsl:if>
		<xsl:apply-templates select="." mode="titleabbrev.markup"/>
	</a>
	</span>
	<!-- add another span to hold the lustre version annotation -->
	<xsl:if test="@condition='l24'">
		<span class='floatright'>L 2.4 </span>
	</xsl:if>
	<xsl:if test="@condition='l23'">
		<span class='floatright'>L 2.3 </span>
	</xsl:if>
</xsl:template>

</xsl:stylesheet>
