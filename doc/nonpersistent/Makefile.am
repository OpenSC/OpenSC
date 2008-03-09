MAINTAINERCLEANFILES = Makefile.in ChangeLog ChangeLog.tmp

wikidir=$(htmldir)/wiki

dist_noinst_SCRIPTS = export-wiki.sh export-wiki.xsl \
	svn2cl.xsl 
dist_wiki_DATA = wiki.out/*
dist_noinst_DATA = ChangeLog

if SVN_CHECKOUT

wiki.out/*:
	test -n "$(WGET)" -a -n "$(SED)" -a -n "$(TR)" -a -n "$(XSLTPROC)"
	WGET="$(WGET)" WGET_OPTS="$(WGET_OPTS)" SED="$(SED)" TR="$(TR)" XSLTPROC="$(XSLTPROC)" \
		PROJECT="@PACKAGE_NAME@" \
		$(SHELL) "$(srcdir)/export-wiki.sh" "$(srcdir)" "$(srcdir)/wiki.tmp"
	mv wiki.tmp wiki.out

ChangeLog:
	test -n "$(SVN)" -a -n "$(XSLTPROC)"
	if test -d .svn; then \
		$(SVN) --verbose --xml log "$(top_srcdir)" | \
			$(XSLTPROC) --nonet --stringparam linelen 75 \
			--stringparam groupbyday no \
			--stringparam include-rev no \
			"$(srcdir)/svn2cl.xsl" - > ChangeLog.tmp; \
	else \
		echo "Warning: Unable to generate ChangeLog from none svn checkout" >&2; \
		echo > ChangeLog.tmp; \
	fi
	mv ChangeLog.tmp ChangeLog

endif

maintainer-clean-local:
	rm -rf wiki.out wiki.tmp
