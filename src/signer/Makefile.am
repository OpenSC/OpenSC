
plugindir = $(PLUGINDIR)

plugin_LTLIBRARIES       = opensc-signer.la
opensc_signer_la_LDFLAGS = -module -avoid-version -lcrypto -lassuan
opensc_signer_la_CFLAGS  = $(AM_CFLAGS) -Inpinclude -DXP_UNIX
opensc_signer_la_SOURCES = opensc-crypto.c opensc-support.c \
			   signer.c stubs.c dialog.c
noinst_HEADERS		 = opensc-crypto.h opensc-support.h \
			   signer.h npinclude/jri.h npinclude/jri_md.h \
			   npinclude/jritypes.h npinclude/npapi.h \
			   npinclude/npupp.h npinclude/npunix.c
