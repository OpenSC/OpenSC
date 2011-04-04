MAINTAINERCLEANFILES = $(srcdir)/Makefile.in \
		$(srcdir)/versioninfo.rc $(srcdir)/winconfig.h
EXTRA_DIST = ltrc.inc Makefile.mak Make.rules.mak opensc-install.bat \
		versioninfo.rc.in winconfig.h.in OpenSC.iss.in OpenSC.wxs.in
dist_noinst_HEADERS = versioninfo.rc winconfig.h

if WIN32
sbin_SCRIPTS = opensc-install.bat
endif
