
plugindir = $(PLUGINDIR)

plugin_LTLIBRARIES       = opensc-signer.la
opensc_signer_la_LDFLAGS = -module -avoid-version -lcrypto -lassuan
opensc_signer_la_CFLAGS  = $(AM_CFLAGS) -Iinclude -DXP_UNIX
opensc_signer_la_SOURCES = opensc-crypto.c opensc-support.c \
			   signer.c stubs.c dialog.c
