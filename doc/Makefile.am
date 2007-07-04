# Process this file with automake to create Makefile.in

SUBDIRS = . 

MAINTAINERCLEANFILES = Makefile.in $(HTML) ChangeLog

EXTRA_DIST = README ChangeLog $(HTML) $(XML) index.html \
		export-wiki.sh export-wiki.xsl \
		generate-man.sh changelog.sh svn2cl.xsl 

HTML= $(shell ls $(srcdir)/*.html $(srcdir)/*.css $(srcdir)/*.gif $(srcdir)/html/*)
XML = $(shell ls $(srcdir)/tools/*.xml $(srcdir)/api/*.xml $(srcdir)/api/*/*.xml $(srcdir)/api/api.css $(srcdir)/api/*.xsl)

index.html:
	sh $(srcdir)/export-wiki.sh $(srcdir)
	sh $(srcdir)/generate-man.sh $(srcdir)

ChangeLog:
	sh $(srcdir)/changelog.sh $(srcdir)

maintainer-clean-local:
	rm -rf $(srcdir)/html
