# Process this file with automake to create Makefile.in

bundledir = @BUNDLEDIR@/pkcs11
libdir = @libdir@/pkcs11
includedir = @includedir@/opensc

MAINTAINERCLEANFILES = Makefile.in

EXTRA_DIST = Makefile.mak opensc_pkcs11_install.js

SUBDIRS = . rsaref

INCLUDES = @CPPFLAGS@ -I${top_srcdir}/src/pkcs15init

SRC = pkcs11-global.c pkcs11-session.c pkcs11-object.c misc.c slot.c \
	mechanism.c openssl.c secretkey.c framework-pkcs15.c \
	framework-pkcs15init.c debug.c
INC = sc-pkcs11.h

lib_LTLIBRARIES = opensc-pkcs11.la libpkcs11.la pkcs11-spy.la

opensc_pkcs11_la_SOURCES = $(SRC) $(INC)
opensc_pkcs11_la_LDFLAGS = -module -avoid-version
opensc_pkcs11_la_LIBADD = @LIBOPENSC@ @LIBCRYPTO@ \
	../pkcs15init/libpkcs15init.la ../scrandom/libscrandom.la

libpkcs11_la_SOURCES = libpkcs11.c
libpkcs11_la_LDFLAGS = -version-info @OPENSC_LT_CURRENT@:@OPENSC_LT_REVISION@:@OPENSC_LT_AGE@
libpkcs11_la_LIBADD = ../scdl/libscdl.la @LIBDL@

pkcs11_spy_la_SOURCES = pkcs11-spy.c pkcs11-display.c pkcs11-display.h
pkcs11_spy_la_LDFLAGS = -module -avoid-version
pkcs11_spy_la_LIBADD = @LIBOPENSC@ @LIBCRYPTO@ libpkcs11.la

include_HEADERS = pkcs11.h

jar-dir:
	if test ! -d jar-dir ; then mkdir jar-dir ; fi

pkcs11-jar: jar-dir
	cp .libs/*.so jar-dir
	cp opensc_pkcs11_install.js jar-dir
	signtool -Z"opensc-pkcs11.jar" -i"opensc_pkcs11_install.js" \
		 -k"testcert" jar-dir

install-exec-local: install-libLTLIBRARIES
if HAVE_BUNDLES
	-${top_srcdir}/macos/libtool-bundle $(DESTDIR)$(libdir)/opensc-pkcs11.so \
		$(DESTDIR)$(bundledir)/
	-${top_srcdir}/macos/libtool-bundle $(DESTDIR)$(libdir)/pkcs11-spy.so \
		$(DESTDIR)$(bundledir)/
endif

uninstall-local: uninstall-libLTLIBRARIES
if HAVE_BUNDLES
	rm -rf $(DESTDIR)$(bundledir)/opensc-pkcs11.bundle/
	rm -rf $(DESTDIR)$(bundledir)/pkcs11-spy.bundle/
endif
