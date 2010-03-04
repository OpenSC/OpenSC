include $(top_srcdir)/win32/ltrc.inc

MAINTAINERCLEANFILES = $(srcdir)/Makefile.in 
EXTRA_DIST = Makefile.mak

if ENABLE_CARDMOD
lib_LTLIBRARIES = opensc-cardmod@LIBRARY_BITNESS@.la
# Do we need this on bin? Why can't we
# put it in dedicated directory
dist_sbin_SCRIPTS = cardmod.inf cardmod-westcos.reg
else
dist_noinst_DATA = cardmod.inf cardmod-westcos.reg
endif

INCLUDES = -I$(top_srcdir)/src

opensc_cardmod@LIBRARY_BITNESS@_la_SOURCES = cardmod.c cardmod.exports \
	$(top_builddir)/win32/versioninfo.rc
opensc_cardmod@LIBRARY_BITNESS@_la_LIBADD =  $(LTLIB_LIBS) \
	$(top_builddir)/src/libopensc/libopensc.la \
	-lcrypt32
opensc_cardmod@LIBRARY_BITNESS@_la_LDFLAGS = $(AM_LDFLAGS) \
	-export-symbols "$(srcdir)/cardmod.exports" \
	-module -avoid-version -no-undefined

if ENABLE_CARDMOD
install-exec-hook:
	mv "$(DESTDIR)$(libdir)/opensc-cardmod@LIBRARY_BITNESS@.dll" "$(DESTDIR)$(bindir)/" 
endif
