## Makefile.am -- Process this file with automake to produce Makefile.in

AUX_DIST		= config.guess config.sub \
			install-sh \
			ltmain.sh \
			missing \
			mkinstalldirs \
			depcomp
EXTRA_DIST		= bootstrap

SUBDIRS			= src
MAINTAINERCLEANFILES	= Makefile.in aclocal.m4 configure config-h.in \
			stamp-h.in $(AUX_DIST)
dist-hook:
	cd $(distdir)
	for file in $(AUX_DIST); do \
	  cp $$file $(distdir)/$$file; \
	done
