<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE stylesheet [
<!ENTITY css SYSTEM "api.css">
]>
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">
	<xsl:import href="docbook-utf8.xsl"/>
	<xsl:param name="toc.section.depth" select="0"/>
	<xsl:param name="generate.consistent.ids" select="1"/>
	<xsl:template name="user.head.content">
	<style type="text/css">
		<xsl:comment>
			&css;
		</xsl:comment>
	</style>
	</xsl:template>
</xsl:stylesheet>
