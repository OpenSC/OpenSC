# Process this file with automake to create Makefile.in

libdir = ${prefix}/lib/pkcs11

MAINTAINERCLEANFILES = Makefile.in

SUBDIRS = . rsaref

if HAVE_SSL
SSL_SRC	= framework-pkcs15init.c
SSL_LIBS = ../pkcs15init/libpkcs15init.la
SSL_INCLUDES = -I../pkcs15init
endif

INCLUDES = @CFLAGS_OPENSC@ $(SSL_INCLUDES)

LDFLAGS = @LDFLAGS@ @LIBDL@ @LIBOPENSC@ $(SSL_LIBS)

SRC = pkcs11-global.c pkcs11-session.c pkcs11-object.c misc.c slot.c \
	secretkey.c framework-pkcs15.c $(SSL_SRC)
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
