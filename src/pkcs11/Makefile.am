# Process this file with automake to create Makefile.in

libdir = @libdir@/pkcs11

MAINTAINERCLEANFILES = Makefile.in

EXTRA_DIST = Makefile.mak opensc_pkcs11_install.js

SUBDIRS = . rsaref

INCLUDES = @CFLAGS_OPENSC@ -I../pkcs15init

SRC = pkcs11-global.c pkcs11-session.c pkcs11-object.c misc.c slot.c \
	mechanism.c openssl.c secretkey.c framework-pkcs15.c \
	framework-pkcs15init.c debug.c
INC = sc-pkcs11.h

lib_LTLIBRARIES = opensc-pkcs11.la libpkcs11.la

opensc_pkcs11_la_SOURCES = $(SRC) $(INC)
opensc_pkcs11_la_LDFLAGS = -module -avoid-version
opensc_pkcs11_la_LIBADD = @LIBDL@ @LIBOPENSC@ \
	../pkcs15init/libpkcs15init.la ../scrandom/libscrandom.la

libpkcs11_la_SOURCES = libpkcs11.c
libpkcs11_la_LDFLAGS = -version-info 0:6:0
libpkcs11_la_LIBADD = @LIBDL@ @LIBOPENSC@ \
	../pkcs15init/libpkcs15init.la ../scrandom/libscrandom.la

openscdir=@includedir@/opensc
opensc_HEADERS = pkcs11.h

jar-dir:
	if test ! -d jar-dir ; then mkdir jar-dir ; fi

pkcs11-jar: jar-dir
	cp .libs/*.so jar-dir
	cp opensc_pkcs11_install.js jar-dir
	signtool -Z"opensc-pkcs11.jar" -i"opensc_pkcs11_install.js" \
		 -k"testcert" jar-dir

install-exec-local: install-libLTLIBRARIES
	-rm -f $(DESTDIR)$(libdir)/opensc-pkcs11.a $(DESTDIR)$(libdir)/opensc-pkcs11.la
