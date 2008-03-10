MAINTAINERCLEANFILES = Makefile.in

wikidir=$(htmldir)/wiki

if ENABLE_DOC
SUBDIRS = nonpersistent
endif
DIST_SUBDIRS = nonpersistent

dist_noinst_DATA = tools/*.xml api/*.xml api/*/*.xml api/api.css api/*.xsl
if ENABLE_DOC
dist_html_DATA = html.out/*
else
dist_noinst_DATA += html.out/*
endif
dist_doc_DATA = README
if WIN32
dist_noinst_DATA += man.out/*.1 man.out/*.3 man.out/*.5
else
dist_man1_MANS = man.out/*.1
dist_man3_MANS = man.out/*.3
dist_man5_MANS = man.out/*.5
endif

if SVN_CHECKOUT
if ENABLE_MAN

html.out/*:	api/xsl-stylesheets
	test -n "$(XSLTPROC)"
	-rm -fr html.tmp
	$(mkdir_p) html.tmp
	$(XSLTPROC) --nonet --xinclude -o "html.out/api.html" "$(srcdir)/api/html.xsl" "$(srcdir)/api/api.xml"
	$(XSLTPROC) --nonet --xinclude -o "html.out/tools.html" "$(srcdir)/api/html.xsl" "$(srcdir)/tools/tools.xml"
	mv html.tmp html.out

man.out/*.1:	api/xsl-stylesheets
	test -n "$(XSLTPROC)"
	-rm -fr man.tmp
	$(mkdir_p) man.tmp
	$(XSLTPROC) --nonet --xinclude -o "man.out/" "$(srcdir)/api/man.xsl" "$(srcdir)/api/api.xml"
	$(XSLTPROC) --nonet --xinclude -o "man.out/" "$(srcdir)/api/man.xsl" "$(srcdir)/tools/tools.xml"
	mv man.tmp man.out

man.out/*.3 man.out/*.5:	man.out/*.1

api/xsl-stylesheets:
	$(LN_S) "$(xslstylesheetsdir)" api/xsl-stylesheets

else

html.out/*:
man.out/*.1:
man.out/*.3 man.out/*.5:	man.out/*.1

endif
endif

maintainer-clean-local:
	rm -rf html.out html.tmp man.out man.tmp
	rm -fr api/xsl-stylesheets
