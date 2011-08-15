MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

dist_noinst_SCRIPTS = html.xsl man.xsl
dist_noinst_DATA = $(srcdir)/tools/*.xml api.css
if ENABLE_DOC
html_DATA = html.out/*
endif

if ENABLE_MAN
man1_MANS = man.out/*.1
man5_MANS = man.out/*.5
endif

html.out/*: html.out
html.out:
	-rm -fr html.tmp html.out
	$(MKDIR_P) html.tmp
	$(XSLTPROC) --nonet --path "$(srcdir):$(xslstylesheetsdir)/html" --xinclude -o "html.tmp/tools.html" "html.xsl" "$(srcdir)/tools/tools.xml"
	mv html.tmp html.out

man.out/*.1: man.out
man.out:
	-rm -fr man.tmp man.out
	$(MKDIR_P) man.tmp
	$(XSLTPROC) --nonet --path "$(srcdir):$(xslstylesheetsdir)/manpages" --xinclude -o "man.tmp/" "man.xsl" "$(srcdir)/tools/tools.xml"
	mv man.tmp man.out

man.out/*.5:	man.out/*.1


clean-local:
	-rm -fr html.tmp man.tmp html.out man.out
