include $(top_srcdir)/win32/ltrc.inc

MAINTAINERCLEANFILES = $(srcdir)/Makefile.in $(srcdir)/winconfig.h \
		$(srcdir)/OpenSC.iss $(srcdir)/OpenSC.wxs
EXTRA_DIST = ltrc.inc Makefile.mak Make.rules.mak versioninfo.rc winconfig.h.in \
		OpenSC.iss.in OpenSC.wxs.in versioninfo-customactions.rc \
		OpenSC.ico dlgbmp.bmp bannrbmp.bmp DDORes.dll_14_2302.ico
dist_noinst_HEADERS = versioninfo.rc winconfig.h OpenSC.iss OpenSC.wxs

if ENABLE_MINIDRIVER_SETUP_CUSTOMACTION
lib_LTLIBRARIES = customactions@LIBRARY_BITNESS@.la

AM_CPPFLAGS = -I$(top_srcdir)


customactions@LIBRARY_BITNESS@_la_SOURCES = customactions.cpp customactions.exports versioninfo-customactions.rc
customactions@LIBRARY_BITNESS@_la_LIBADD =  \
	$(top_builddir)/win32/customactions.la
customactions@LIBRARY_BITNESS@_la_LDFLAGS = $(AM_LDFLAGS) \
	-export-symbols "$(srcdir)/customactions.exports" \
	-module -avoid-version -no-undefined

install-exec-hook:
	mv "$(DESTDIR)$(libdir)/customactions@LIBRARY_BITNESS@.dll" "$(DESTDIR)$(bindir)/"

uninstall-hook:
	rm -f "$(DESTDIR)$(bindir)/customactions@LIBRARY_BITNESS@.dll"
endif
