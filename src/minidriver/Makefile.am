include $(top_srcdir)/win32/ltrc.inc

MAINTAINERCLEANFILES = $(srcdir)/Makefile.in $(srcdir)/versioninfo-minidriver.rc
EXTRA_DIST = Makefile.mak versioninfo-minidriver.rc.in opensc-minidriver.dll.manifest

if ENABLE_MINIDRIVER
lib_LTLIBRARIES = opensc-minidriver@LIBRARY_BITNESS@.la
# Do we need this on bin? Why can't we
# put it in dedicated directory
dist_sbin_SCRIPTS = opensc-minidriver.inf
else
dist_noinst_DATA = opensc-minidriver.inf
endif

AM_CFLAGS = $(OPTIONAL_OPENSSL_CFLAGS) $(OPENPACE_CFLAGS)
AM_CPPFLAGS = -I$(top_srcdir)/src

opensc_minidriver@LIBRARY_BITNESS@_la_SOURCES = minidriver.c minidriver.exports versioninfo-minidriver.rc
opensc_minidriver@LIBRARY_BITNESS@_la_LIBADD =  \
	$(top_builddir)/src/libopensc/libopensc_static.la \
	$(OPTIONAL_OPENSSL_LIBS) \
	-lbcrypt -lcrypt32 -lrpcrt4 -lwinmm
opensc_minidriver@LIBRARY_BITNESS@_la_LDFLAGS = $(AM_LDFLAGS) \
	-export-symbols "$(srcdir)/minidriver.exports" \
	-module -avoid-version -no-undefined

if ENABLE_MINIDRIVER
install-exec-hook:
	mv "$(DESTDIR)$(libdir)/opensc-minidriver@LIBRARY_BITNESS@.dll" "$(DESTDIR)$(bindir)/"

uninstall-hook:
	rm -f "$(DESTDIR)$(bindir)/opensc-minidriver@LIBRARY_BITNESS@.dll"
endif
