MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

wikidir=$(htmldir)/wiki

if ENABLE_DOC
SUBDIRS = nonpersistent
endif
DIST_SUBDIRS = nonpersistent

dist_noinst_DATA = $(srcdir)/tools/*.xml \
	$(srcdir)/api/*.xml \
	$(srcdir)/api/apps/*.xml \
	$(srcdir)/api/asn1/*.xml \
	$(srcdir)/api/card/*.xml \
	$(srcdir)/api/file/*.xml \
	$(srcdir)/api/init/*.xml \
	$(srcdir)/api/misc/*.xml \
	$(srcdir)/api/types/*.xml \
	$(srcdir)/api/util/*.xml \
	$(srcdir)/api/api.css \
	$(srcdir)/api/*.xsl

if ENABLE_DOC
dist_html_DATA = html.out/*
else
dist_noinst_DATA += html.out/*
endif
dist_doc_DATA = README

if ENABLE_MAN
if WIN32
dist_noinst_DATA += man.out/*.1 man.out/*.3 man.out/*.5
else
dist_man1_MANS = man.out/*.1
dist_man3_MANS = man.out/*.3
dist_man5_MANS = man.out/*.5
endif
endif

if SVN_CHECKOUT
if ENABLE_MAN

html.out/*: html.out
html.out: api.work
	test -n "$(XSLTPROC)"
	-rm -fr html.tmp html.out
	$(MKDIR_P) html.tmp
	$(XSLTPROC) --nonet --path "$(srcdir)/api" --xinclude -o "html.tmp/api.html" "api.work/html.xsl" "$(srcdir)/api/api.xml"
	$(XSLTPROC) --nonet --path "$(srcdir)/api" --xinclude -o "html.tmp/tools.html" "api.work/html.xsl" "$(srcdir)/tools/tools.xml"
	mv html.tmp html.out

man.out/*.1: man.out
man.out: api.work
	test -n "$(XSLTPROC)"
	-rm -fr man.tmp man.out
	$(MKDIR_P) man.tmp
	$(XSLTPROC) --nonet --path "$(srcdir)/api" --xinclude -o "man.tmp/" "api.work/man.xsl" "$(srcdir)/api/api.xml"
	$(XSLTPROC) --nonet --path "$(srcdir)/api" --xinclude -o "man.tmp/" "api.work/man.xsl" "$(srcdir)/tools/tools.xml"
	mv man.tmp man.out

man.out/*.3 man.out/*.5:	man.out/*.1

#
# This part is needed as found no
# way to make xsltproc find xsl-stylesheets
# in builddir while xsl on srcdir
#
api.work:	\
		$(abs_srcdir)/api/html.xsl \
		$(abs_srcdir)/api/man.xsl
	-rm -fr api.work
	$(MKDIR_P) api.work
	$(LN_S) "$(abs_srcdir)/api/html.xsl" api.work/html.xsl
	$(LN_S) "$(abs_srcdir)/api/man.xsl" api.work/man.xsl
	$(LN_S) "$(xslstylesheetsdir)" api.work/xsl-stylesheets

else

html.out/*:
man.out/*.1:
man.out/*.3 man.out/*.5:	man.out/*.1

endif
else

html.out/*:	$(abs_builddir)/html.out
$(abs_builddir)/html.out:
	$(LN_S) "$(srcdir)/html.out" html.out

man.out/*.3 man.out/*.5 man.out/*.1:	$(abs_builddir)/man.out
$(abs_builddir)/man.out:
	$(LN_S) "$(srcdir)/man.out" man.out

endif

maintainer-clean-local:
	-rm -rf "$(srcdir)/html.out" "$(srcdir)/man.out"

distclean-local:
	-rm -fr html.tmp man.tmp api.work
	if test -L html.out; then \
		rm -rf html.out; \
	fi
	if test -L man.out; then \
		rm -rf man.out; \
	fi

