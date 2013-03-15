MAINTAINERCLEANFILES = $(srcdir)/Makefile.in $(srcdir)/versioninfo.rc $(srcdir)/winconfig.h \
		$(srcdir)/OpenSC.iss $(srcdir)/OpenSC.wxs $(srcdir)/OpenSC.ico $(srcdir)/license.rtf
EXTRA_DIST = ltrc.inc Makefile.mak Make.rules.mak opensc-install.bat \
		versioninfo.rc.in winconfig.h.in OpenSC.iss.in OpenSC.wxs.in
dist_noinst_HEADERS = versioninfo.rc winconfig.h OpenSC.iss OpenSC.wxs license.rtf OpenSC.ico

if WIN32
sbin_SCRIPTS = opensc-install.bat
endif
