# Process this file with automake to create Makefile.in

SUBDIRS = . rsaref

libdir = ${prefix}/lib/pkcs11

INCLUDES = @CFLAGS_PCSC@ @CFLAGS_OPENSC@

LDFLAGS = @LDFLAGS@ @LIBDL@ @LIBOPENSC@

SRC = pkcs11-global.c pkcs11-session.c pkcs11-object.c misc.c slot.c \
	framework-pkcs15.c
INC = sc-pkcs11.h

lib_LTLIBRARIES = opensc-pkcs11.la

opensc_pkcs11_la_SOURCES = $(SRC) $(INC)
opensc_pkcs11_la_LDFLAGS = -module -avoid-version

jar-dir:
	if test ! -d jar-dir ; then mkdir jar-dir ; fi

pkcs11-jar: jar-dir
	cp .libs/*.so jar-dir
	cp opensc_pkcs11_install.js jar-dir
	signtool -Z"opensc-pkcs11.jar" -i"opensc_pkcs11_install.js" \
		 -k"testcert" jar-dir

install-exec-local: install-libLTLIBRARIES
	-rm -f $(DESTDIR)$(libdir)/opensc-pkcs11.a $(DESTDIR)$(libdir)/opensc-pkcs11.la
