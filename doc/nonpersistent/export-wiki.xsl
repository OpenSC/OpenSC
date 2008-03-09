<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0"
xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
xmlns="http://www.w3.org/1999/xhtml"
xmlns:html="http://www.w3.org/1999/xhtml">
	<xsl:output method="html" indent="yes"/>
  
  <xsl:template match="/">
    <xsl:apply-templates />
  </xsl:template>
  
  <xsl:template match="/html:html">
      <html>
        <head>
          <title><xsl:value-of select="/html:html/html:head/html:title" /></title>
          <style type="text/css">
           @import url(trac.css);
          </style>
        </head>
        <body>
          <xsl:apply-templates select="//html:div[@class='wiki']" />
          <div class="footer">
            <hr />
            <p><a href="index.html">Back to Index</a></p>
          </div>
        </body>
      </html>
  </xsl:template>
  
  <xsl:template match="/pages">
      <html>
        <head>
          <title>Wiki Index</title>
          <style type="text/css">
           @import url(trac.css);
          </style>
        </head>
        <body>
          <h1>Index of Wiki Pages</h1>
          <ul>
          <xsl:apply-templates select="page" />
          </ul>
        </body>
      </html>
  </xsl:template>
  
  <xsl:template match="page">
    <li><a href="{.}.html"><xsl:value-of select="." /></a></li>
  </xsl:template>
  
  <xsl:template match="node()|@*" priority="-1">
    <xsl:copy>
      <xsl:apply-templates select="@*|node()"/>
    </xsl:copy>
  </xsl:template>
 
</xsl:stylesheet>

