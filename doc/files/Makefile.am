MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

dist_noinst_DATA = pkcs15-profile.5.xml opensc.conf.5.xml.in files.xml
if ENABLE_DOC
html_DATA = files.html
endif

if ENABLE_MAN
man5_MANS = pkcs15-profile.5  opensc.conf.5
endif

opensc.conf.5.xml opensc.conf.5: $(srcdir)/opensc.conf.5.xml.in
	sed \
		-e 's|@sysconfdir[@]|$(sysconfdir)|g' \
		-e 's|@docdir[@]|$(docdir)|g' \
		-e 's|@libdir[@]|$(libdir)|g' \
		-e 's|@DYN_LIB_EXT[@]|$(DYN_LIB_EXT)|g' \
		-e 's|@DEFAULT_PCSC_PROVIDER[@]|$(DEFAULT_PCSC_PROVIDER)|g' \
		-e 's|@PROFILE_DIR_DEFAULT[@]|$(PROFILE_DIR_DEFAULT)|g' \
		-e 's|@DEFAULT_SM_MODULE[@]|$(DEFAULT_SM_MODULE)|g' \
		< $< > opensc.conf.5.xml
	$(XSLTPROC) --nonet --path "$(srcdir)/..:$(xslstylesheetsdir)/manpages" --xinclude -o $@ man.xsl opensc.conf.5.xml

files.html: $(srcdir)/files.xml $(wildcard $(srcdir)/*.5.xml) opensc.conf.5.xml
	$(XSLTPROC) --nonet --path "$(builddir):$(srcdir)/..:$(xslstylesheetsdir)/html" --xinclude -o $@ html.xsl $<

%.5: $(srcdir)/%.5.xml
	sed -e 's|@pkgdatadir[@]|$(pkgdatadir)|g' < $< \
	| $(XSLTPROC) --nonet --path "$(srcdir)/..:$(xslstylesheetsdir)/manpages" --xinclude -o $@ man.xsl $<

clean-local:
	-rm -rf $(html_DATA) $(man5_MANS) opensc.conf.5.xml
