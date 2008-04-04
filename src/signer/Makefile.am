MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

SUBDIRS = npinclude
if ENABLE_NSPLUGIN
noinst_HEADERS = opensc-crypto.h opensc-support.h signer.h 
lib_LTLIBRARIES = opensc-signer.la
dist_noinst_DATA = testprog.c
endif

AM_CFLAGS = $(OPENSSL_CFLAGS) $(LIBASSUAN_CFLAGS)
INCLUDES = -I$(srcdir)/npinclude -I$(top_builddir)/src/include

opensc_signer_la_CFLAGS = $(AM_CFLAGS) -DXP_UNIX
opensc_signer_la_SOURCES = opensc-crypto.c opensc-support.c signer.c stubs.c dialog.c \
	signer.exports
opensc_signer_la_LIBADD = $(OPENSSL_LIBS) $(LIBASSUAN_LIBS) \
	$(top_builddir)/src/libopensc/libopensc.la
opensc_signer_la_LDFLAGS = $(AM_LDFLAGS) \
	-export-symbols "$(srcdir)/signer.exports" \
	-module -avoid-version -no-undefined

if ENABLE_NSPLUGIN
plugin_DATA=#Create directory
install-exec-hook:	install-pluginDATA
	-rm -f "$(DESTDIR)$(plugindir)/opensc-signer.so"
	$(LN_S) "$(libdir)/opensc-signer.so" "$(DESTDIR)$(plugindir)"
endif
