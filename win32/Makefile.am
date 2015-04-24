MAINTAINERCLEANFILES = $(srcdir)/Makefile.in $(srcdir)/versioninfo.rc $(srcdir)/winconfig.h \
		$(srcdir)/OpenSC.iss $(srcdir)/OpenSC.wxs $(srcdir)/OpenSC.ico $(srcdir)/license.rtf
EXTRA_DIST = ltrc.inc Makefile.mak Make.rules.mak opensc-install.bat \
		versioninfo.rc.in winconfig.h.in OpenSC.iss.in OpenSC.wxs.in
dist_noinst_HEADERS = versioninfo.rc winconfig.h OpenSC.iss OpenSC.wxs license.rtf OpenSC.ico

if WIN32
sbin_SCRIPTS = opensc-install.bat
endif

lib_LTLIBRARIES = opensc-setup-custom-action@LIBRARY_BITNESS@.la

AM_CPPFLAGS = -I$(top_srcdir)/win32


opensc-setup-custom-action@LIBRARY_BITNESS@_la_SOURCES = opensc-setup-custom-action.c opensc-setup-custom-action.exports
opensc-setup-custom-action@LIBRARY_BITNESS@_la_LIBADD =  \
	$(top_builddir)/win32/opensc-setup-custom-action.la
opensc-setup-custom-action@LIBRARY_BITNESS@_la_LDFLAGS = $(AM_LDFLAGS) \
	-export-symbols "$(srcdir)/win32/opensc-setup-custom-action.exports" \
	-module -avoid-version -no-undefined

if ENABLE_MINIDRIVER
install-exec-hook:
	mv "$(DESTDIR)$(libdir)/opensc-setup-custom-action@LIBRARY_BITNESS@.dll" "$(DESTDIR)$(bindir)/"
endif
