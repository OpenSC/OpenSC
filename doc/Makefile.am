# Process this file with automake to create Makefile.in

SUBDIRS = . old src

MAINTAINERCLEANFILES = Makefile.in $(HTML)

EXTRA_DIST = README export-wiki.sh export-wiki.xsl generate-man.sh \
		$(HTML) $(XML) index.html

HTML= $(shell ls $(srcdir)/*.html $(srcdir)/*.css)
XML = $(shell ls tools/*.xml api/*.xml api/*/*.xml api/api.css api/*.xsl)

index.html:
	sh $(srcdir)/export-wiki.sh $(srcdir)
	sh $(srcdir)/generate-man.sh $(srcdir)
	sh $(srcdir)/old/generate.sh $(srcdir)/old

maintainer-clean-local:
	rm -rf $(srcdir)/html
