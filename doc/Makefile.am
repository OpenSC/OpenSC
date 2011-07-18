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
html.out: api.work
	-rm -fr html.tmp html.out
	$(MKDIR_P) html.tmp
	$(XSLTPROC) --nonet --path "$(srcdir)/api" --xinclude -o "html.tmp/tools.html" "api.work/html.xsl" "$(srcdir)/tools/tools.xml"
	mv html.tmp html.out

man.out/*.1: man.out
man.out: api.work
	-rm -fr man.tmp man.out
	$(MKDIR_P) man.tmp
	$(XSLTPROC) --nonet --path "$(srcdir)/api" --xinclude -o "man.tmp/" "api.work/man.xsl" "$(srcdir)/tools/tools.xml"
	mv man.tmp man.out

man.out/*.5:	man.out/*.1

#
# This part is needed as found no
# way to make xsltproc find xsl-stylesheets
# in builddir while xsl on srcdir
#
api.work:	\
		$(abs_srcdir)/html.xsl \
		$(abs_srcdir)/man.xsl \
		$(abs_srcdir)/api.css
	-rm -fr api.work
	$(MKDIR_P) api.work
	$(LN_S) "$(abs_srcdir)/html.xsl" api.work/html.xsl
	$(LN_S) "$(abs_srcdir)/man.xsl" api.work/man.xsl
	$(LN_S) "$(abs_srcdir)/api.css" api.work/api.css
	$(LN_S) "$(xslstylesheetsdir)" api.work/xsl-stylesheets

clean-local:
	-rm -fr html.tmp man.tmp api.work html.out man.out
