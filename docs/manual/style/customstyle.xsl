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


<!-- include our decoration style for Lustre versions. -->
<xsl:include href='./style/customstyle_common.xsl'/>

<xsl:template match="*[@condition]">
	<xsl:param name="content">
		<xsl:apply-imports/>
	</xsl:param>

	<xsl:call-template name='condition-decorator'>
		<xsl:with-param name='content' select="$content"/>
	</xsl:call-template>
</xsl:template>

</xsl:stylesheet>
