# Process this file with automake to create Makefile.in

plugindir = @PLUGINDIR@
libdir = @libdir@/opensc

MAINTAINERCLEANFILES = Makefile.in

SUBDIRS = . npinclude

EXTRA_DIST = testprog.c

INCLUDES = @CPPFLAGS@ @CFLAGS_ASSUAN@

if HAVE_SSL
if HAVE_ASSUAN
lib_LTLIBRARIES = opensc-signer.la
endif
endif

opensc_signer_la_LDFLAGS = -module -avoid-version
opensc_signer_la_LIBADD = @LIBOPENSC@ @LIBCRYPTO@ @LIBASSUAN@
opensc_signer_la_CFLAGS = $(AM_CFLAGS) -Inpinclude -DXP_UNIX
opensc_signer_la_SOURCES = \
	opensc-crypto.c opensc-support.c signer.c stubs.c dialog.c
noinst_HEADERS = \
	opensc-crypto.h opensc-support.h signer.h 

install-exec-local: install-libLTLIBRARIES
	-$(LN_S) -f $(libdir)/opensc-signer.so $(DESTDIR)$(plugindir)/
