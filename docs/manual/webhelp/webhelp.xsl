<?xml version="1.0"?>
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                xmlns:doc="http://nwalsh.com/xsl/documentation/1.0"
                xmlns:exsl="http://exslt.org/common"
                xmlns:set="http://exslt.org/sets"
		version="1.0"
                exclude-result-prefixes="doc exsl set">

<!-- ********************************************************************
     $Id$
     ******************************************************************** 

     This file is part customization layer on top of the XSL DocBook
     Stylesheet distribution that generates webhelp output.

     ******************************************************************** -->

<xsl:import href="xhtml/chunk.xsl"/>
<xsl:include href="webhelp-common.xsl"/>
<xsl:include href="xhtml/titlepage.templates.xsl"/>

<xsl:param name="webhelp.base.dir">../webhelp-out</xsl:param>
<xsl:param name="html.stylesheet">../style/manual.css</xsl:param>

<!-- include our decoration style for Lustre versions. -->
<xsl:include href='../style/customstyle_common.xsl'/>


<!-- only match if the node doesn't qualify for chunking, 
     it does have a 'condition' attribute -->
<!--xsl:template match='*[not(self::set|self::self::book|self::part|self::preface|self::chapter|self::appendix|self::article|self::topic|self::reference|self::refentry|self::book/glossary|self::article/glossary|self::part/glossary|self::book/bibliography|self::article/bibliography|self::part/bibliography|self::colophon)]@condition]'-->
<!-- however, I can't get this to work, so instead, I will
     just select the set that shouldn't find them selves being chunked.
	 This is not the right way to do this, and should be fixed. -->

<xsl:template match="*[self::para|self::glossentry|self::warning|self::note][@condition]">
    <xsl:param name="content">
        <xsl:apply-imports/>
    </xsl:param>

    <xsl:call-template name='condition-decorator'>
        <xsl:with-param name='content' select="$content"/>
    </xsl:call-template>
</xsl:template>

</xsl:stylesheet>
