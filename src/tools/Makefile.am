# Process this file with automake to create Makefile.in

MAINTAINERCLEANFILES = Makefile.in

EXTRA_DIST = Makefile.mak

AM_LDFLAGS = @LIBOPENSC@

if HAVE_SSL
PROGRAMS_SSL = cryptoflex-tool pkcs15-init
endif

bin_PROGRAMS = opensc-tool opensc-explorer pkcs15-tool pkcs15-crypt \
	pkcs11-tool cardos-info \
	$(PROGRAMS_SSL)

opensc_tool_SOURCES = opensc-tool.c util.c
opensc_tool_LDADD = @GETOPTSRC@
opensc_explorer_SOURCES = opensc-explorer.c util.c
opensc_explorer_LDADD = @GETOPTSRC@ @LIBREADLINE@
pkcs15_tool_SOURCES = pkcs15-tool.c util.c
pkcs15_tool_LDADD = @GETOPTSRC@
pkcs11_tool_SOURCES = pkcs11-tool.c util.c
pkcs11_tool_LDADD = @GETOPTSRC@ ../pkcs11/libpkcs11.la @LIBCRYPTO@
pkcs15_crypt_SOURCES = pkcs15-crypt.c util.c
pkcs15_crypt_LDADD = @GETOPTSRC@ @LIBCRYPTO@
cryptoflex_tool_SOURCES = cryptoflex-tool.c util.c
cryptoflex_tool_LDADD = @GETOPTSRC@ @LIBCRYPTO@
pkcs15_init_SOURCES = pkcs15-init.c util.c
pkcs15_init_LDADD = @GETOPTSRC@ @LIBCRYPTO@ ../pkcs15init/libpkcs15init.la
cardos_info_SOURCES = cardos-info.c util.c
cardos_info_LDADD = @GETOPTSRC@

noinst_HEADERS = util.h
