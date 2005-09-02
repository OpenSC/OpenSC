# Process this file with automake to create Makefile.in

SUBDIRS = . old src

MAINTAINERCLEANFILES = Makefile.in $(HTML)

EXTRA_DIST = README export-wiki.sh export-wiki.xsl $(HTML) index.html

HTML= $(shell ls $(srcdir)/*.html $(srcdir)/*.css)

index.html:
	sh $(srcdir)/export-wiki.sh $(srcdir)
	sh $(srcdir)/old/generate.sh $(srcdir)/old
