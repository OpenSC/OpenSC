## Makefile.am -- Process this file with automake to produce Makefile.in

SUBDIRS = . npinclude

EXTRA_DIST = testprog.c

INCLUDES = @CFLAGS_OPENSC@ @CFLAGS_ASSUAN@

plugindir = $(PLUGINDIR)

if HAVE_SSL
plugin_LTLIBRARIES = opensc-signer.la
endif

opensc_signer_la_LDFLAGS = -module -avoid-version
opensc_signer_la_LIBADD = @LIBOPENSC@ @LIBCRYPTO@ @LIBASSUAN@
opensc_signer_la_CFLAGS = $(AM_CFLAGS) -Inpinclude -DXP_UNIX
opensc_signer_la_SOURCES = opensc-crypto.c opensc-support.c \
			   signer.c stubs.c dialog.c
noinst_HEADERS		 = opensc-crypto.h opensc-support.h \
			   signer.h npinclude/jri.h npinclude/jri_md.h \
			   npinclude/jritypes.h npinclude/npapi.h \
			   npinclude/npupp.h npinclude/npunix.c

install-exec-local: install-pluginLTLIBRARIES
	-rm -f $(DESTDIR)$(plugindir)/opensc-signer.a $(DESTDIR)$(plugindir)/opensc-signer.la
