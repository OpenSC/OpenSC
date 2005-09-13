# Process this file with automake to create Makefile.in

SUBDIRS = . old 

MAINTAINERCLEANFILES = Makefile.in $(HTML) ChangeLog

EXTRA_DIST = README ChangeLog $(HTML) $(XML) index.html \
		export-wiki.sh export-wiki.xsl \
		generate-man.sh changelog.sh svn2cl.xsl 

HTML= $(shell ls $(srcdir)/*.html $(srcdir)/*.css $(srcdir)/html/*)
XML = $(shell ls tools/*.xml api/*.xml api/*/*.xml api/api.css api/*.xsl)

index.html:
	sh $(srcdir)/export-wiki.sh $(srcdir)
	sh $(srcdir)/generate-man.sh $(srcdir)
	sh $(srcdir)/old/generate.sh $(srcdir)/old

ChangeLog:
	sh $(srcdir)/changelog.sh $(srcdir)

maintainer-clean-local:
	rm -rf $(srcdir)/html
