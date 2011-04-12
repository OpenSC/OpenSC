include $(top_srcdir)/win32/ltrc.inc

MAINTAINERCLEANFILES = $(srcdir)/Makefile.in
EXTRA_DIST = Makefile.mak

if ENABLE_MINIDRIVER
lib_LTLIBRARIES = opensc-minidriver@LIBRARY_BITNESS@.la
# Do we need this on bin? Why can't we
# put it in dedicated directory
dist_sbin_SCRIPTS = opensc-minidriver.inf minidriver-westcos.reg
else
dist_noinst_DATA = opensc-minidriver.inf minidriver-westcos.reg
endif

INCLUDES = -I$(top_srcdir)/src

opensc_minidriver@LIBRARY_BITNESS@_la_SOURCES = minidriver.c minidriver.exports \
	$(top_builddir)/win32/versioninfo.rc
opensc_minidriver@LIBRARY_BITNESS@_la_LIBADD =  $(LTLIB_LIBS) \
	$(top_builddir)/src/libopensc/libopensc.la \
	-lcrypt32
opensc_minidriver@LIBRARY_BITNESS@_la_LDFLAGS = $(AM_LDFLAGS) \
	-export-symbols "$(srcdir)/minidriver.exports" \
	-module -avoid-version -no-undefined

if ENABLE_MINIDRIVER
install-exec-hook:
	mv "$(DESTDIR)$(libdir)/opensc-minidriver@LIBRARY_BITNESS@.dll" "$(DESTDIR)$(bindir)/"
endif
