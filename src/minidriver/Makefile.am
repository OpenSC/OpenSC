include $(top_srcdir)/win32/ltrc.inc

MAINTAINERCLEANFILES = $(srcdir)/Makefile.in $(srcdir)/versioninfo-minidriver.rc
EXTRA_DIST = Makefile.mak versioninfo-minidriver.rc.in

if ENABLE_MINIDRIVER
lib_LTLIBRARIES = opensc-minidriver@LIBRARY_BITNESS@.la
# Do we need this on bin? Why can't we
# put it in dedicated directory
dist_sbin_SCRIPTS = opensc-minidriver.inf minidriver-westcos.reg minidriver-sc-hsm.reg minidriver-feitian.reg
else
dist_noinst_DATA = opensc-minidriver.inf minidriver-westcos.reg minidriver-sc-hsm.reg minidriver-feitian.reg
endif

AM_CPPFLAGS = -I$(top_srcdir)/src

opensc_minidriver@LIBRARY_BITNESS@_la_SOURCES = minidriver.c minidriver.exports versioninfo-minidriver.rc
opensc_minidriver@LIBRARY_BITNESS@_la_LIBADD =  \
	$(top_builddir)/src/libopensc/libopensc.la \
	-lcrypt32
opensc_minidriver@LIBRARY_BITNESS@_la_LDFLAGS = $(AM_LDFLAGS) \
	-export-symbols "$(srcdir)/minidriver.exports" \
	-module -avoid-version -no-undefined

if ENABLE_MINIDRIVER
install-exec-hook:
	mv "$(DESTDIR)$(libdir)/opensc-minidriver@LIBRARY_BITNESS@.dll" "$(DESTDIR)$(bindir)/"
endif
