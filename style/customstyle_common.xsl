<?xml version='1.0'?>
<xsl:stylesheet  xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns="http://www.w3.org/1999/xhtml" version="1.0">


<!--  textdecoration-1 applies the style to the text to highlight an region
		of the documentation refers to a lustre specific version.

		the overall purpose of this custom style is to add 
		decoration to the rendered version of the manual to show lustre version
		specific features. This is used in the manual docbook markup by
		adding a condition='lNM' element to a node. When rendered,
		the node contents is decorated to indicate it is only available in
 		the N.M version of lustre. -->

<!-- textdecoration-1: a template to apply a div with a class
		around the relevant sections of text. -->
<xsl:template name='textdecoration-1'>
	<xsl:param name='version'/>
	<xsl:param name='content'/>
	<div class='versionbox'>
		<span class='versionlabel'>
			<xsl:value-of select='$version'/>
		</span>
		<span class='versioncontent'>
			<xsl:copy-of select="$content"/>
		</span>
	</div>
</xsl:template>

<!-- conditional matching template: this calls text decoration
     template with the correct variables. -->
<xsl:template name="condition-decorator">
	<xsl:param name='content'/>
	<xsl:choose>
		<xsl:when test="@condition = 'l23'">
			<xsl:call-template name='textdecoration-1'>
				<xsl:with-param name='version' select="'Introduced in Lustre 2.3'"/>
				<xsl:with-param name='content' select="$content"/>
			</xsl:call-template>
		</xsl:when>
		<xsl:when test="@condition = 'l24'">
			<xsl:call-template name='textdecoration-1'>
				<xsl:with-param name='version' select="'Introduced in Lustre 2.4'"/>
				<xsl:with-param name='content' select="$content"/>
			</xsl:call-template>
		</xsl:when>
		<xsl:when test="@condition = 'l25'">
			<xsl:call-template name='textdecoration-1'>
				<xsl:with-param name='version' select="'Introduced in Lustre 2.5'"/>
				<xsl:with-param name='content' select="$content"/>
			</xsl:call-template>
		</xsl:when>
		<xsl:when test="@condition = 'l26'">
			<xsl:call-template name='textdecoration-1'>
				<xsl:with-param name='version' select="'Introduced in Lustre 2.6'"/>
				<xsl:with-param name='content' select="$content"/>
			</xsl:call-template>
		</xsl:when>
		<xsl:when test="@condition = 'l27'">
			<xsl:call-template name='textdecoration-1'>
				<xsl:with-param name='version' select="'Introduced in Lustre 2.7'"/>
				<xsl:with-param name='content' select="$content"/>
			</xsl:call-template>
		</xsl:when>
		<xsl:when test="@condition = 'l28'">
			<xsl:call-template name='textdecoration-1'>
				<xsl:with-param name='version' select="'Introduced in Lustre 2.8'"/>
				<xsl:with-param name='content' select="$content"/>
			</xsl:call-template>
		</xsl:when>
		<xsl:when test="@condition = 'l29'">
			<xsl:call-template name='textdecoration-1'>
				<xsl:with-param name='version' select="'Introduced in Lustre 2.9'"/>
				<xsl:with-param name='content' select="$content"/>
			</xsl:call-template>
		</xsl:when>
		<xsl:when test="@condition = 'l2A'">
			<xsl:call-template name='textdecoration-1'>
				<xsl:with-param name='version' select="'Introduced in Lustre 2.10'"/>
				<xsl:with-param name='content' select="$content"/>
			</xsl:call-template>
		</xsl:when>
		<xsl:when test="@condition = 'l2B'">
			<xsl:call-template name='textdecoration-1'>
				<xsl:with-param name='version' select="'Introduced in Lustre 2.11'"/>
				<xsl:with-param name='content' select="$content"/>
			</xsl:call-template>
		</xsl:when>
		<xsl:when test="@condition = 'l2C'">
			<xsl:call-template name='textdecoration-1'>
				<xsl:with-param name='version' select="'Introduced in Lustre 2.12'"/>
				<xsl:with-param name='content' select="$content"/>
			</xsl:call-template>
		</xsl:when>
		<xsl:when test="@condition != ''">
			<xsl:call-template name='textdecoration-1'>
				<xsl:with-param name='version' select="'Introduced before Lustre 2.3'"/>
				<xsl:with-param name='content' select="$content"/>
			</xsl:call-template>
		</xsl:when>
		<xsl:otherwise>
			<xsl:copy-of select="$content"/>
		</xsl:otherwise>
	</xsl:choose>
</xsl:template>

<!-- toc.line template: This template over loads the behavior of creating the table of contents. It
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
	<xsl:call-template name="condition-title">
		<xsl:with-param name="condition" select="@condition"/>
	</xsl:call-template>
</xsl:template>

<xsl:template name="condition-title">
	<xsl:param name='condition'/>
	<!-- add another span to hold the lustre version annotation -->
	<xsl:choose>
		<xsl:when test="$condition = 'l23'">
			<span class='floatright'>L 2.3 </span>
		</xsl:when>
		<xsl:when test="$condition = 'l24'">
			<span class='floatright'>L 2.4 </span>
		</xsl:when>
		<xsl:when test="$condition = 'l25'">
			<span class='floatright'>L 2.5 </span>
		</xsl:when>
		<xsl:when test="$condition = 'l26'">
			<span class='floatright'>L 2.6 </span>
		</xsl:when>
		<xsl:when test="$condition = 'l27'">
			<span class='floatright'>L 2.7 </span>
		</xsl:when>
		<xsl:when test="$condition = 'l28'">
			<span class='floatright'>L 2.8 </span>
		</xsl:when>
		<xsl:when test="$condition = 'l29'">
			<span class='floatright'>L 2.9 </span>
		</xsl:when>
		<xsl:when test="$condition = 'l2A'">
			<span class='floatright'>L 2.10 </span>
		</xsl:when>
		<xsl:when test="$condition = 'l2B'">
			<span class='floatright'>L 2.11 </span>
		</xsl:when>
		<xsl:when test="$condition = 'l2C'">
			<span class='floatright'>L 2.12 </span>
		</xsl:when>
		<xsl:when test="$condition != ''">
			<span class='floatright'>L ?.? </span>
		</xsl:when>
		<xsl:otherwise>
		</xsl:otherwise>
	</xsl:choose>
</xsl:template>

</xsl:stylesheet>
