## Makefile.am -- Process this file with automake to produce Makefile.in

AUX_DIST		= $(ac_aux_dir)/config.guess \
			$(ac_aux_dir)/config.sub \
			$(ac_aux_dir)/install-sh \
			$(ac_aux_dir)/ltmain.sh \
			$(ac_aux_dir)/missing \
			$(ac_aux_dir)/mkinstalldirs
EXTRA_DIST		= bootstrap

SUBDIRS			= src
MAINTAINERCLEANFILES	= Makefile.in aclocal.m4 configure config-h.in \
			stamp-h.in $(AUX_DIST)
dist-hook:
	(cd $(distdir) && mkdir $(ac_aux_dir))
	for file in $(AUX_DIST); do \
	  cp $$file $(distdir)/$$file; \
	done
