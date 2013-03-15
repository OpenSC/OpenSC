MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

dist_noinst_DATA = $(wildcard $(srcdir)/*.xml)
if ENABLE_DOC
html_DATA = tools.html
endif

if ENABLE_MAN
man1_MANS = $(patsubst $(srcdir)/%.xml, %, $(wildcard $(srcdir)/*.1.xml))
man5_MANS = $(patsubst $(srcdir)/%.xml, %, $(wildcard $(srcdir)/*.5.xml))
endif

tools.html: $(srcdir)/tools.xml $(wildcard $(srcdir)/*.1.xml) $(wildcard $(srcdir)/*.5.xml)
	$(XSLTPROC) --nonet --path "$(srcdir)/..:$(xslstylesheetsdir)/html" --xinclude -o $@ html.xsl $<

%.1: $(srcdir)/%.1.xml
	sed -e 's|@pkgdatadir[@]|$(pkgdatadir)|g' < $< \
	| $(XSLTPROC) --nonet --path "$(srcdir)/..:$(xslstylesheetsdir)/manpages" --xinclude -o $@ man.xsl $<

%.5: $(srcdir)/%.5.xml
	sed -e 's|@pkgdatadir[@]|$(pkgdatadir)|g' < $< \
	| $(XSLTPROC) --nonet --path "$(srcdir)/..:$(xslstylesheetsdir)/manpages" --xinclude -o $@ man.xsl $<

clean-local:
	-rm -rf $(html_DATA) $(man1_MANS) $(man5_MANS)
