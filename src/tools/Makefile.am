# Process this file with automake to create Makefile.in

INCLUDES = @CFLAGS_OPENSC@
LDFLAGS = @LDFLAGS@ @LIBOPENSC@

EXTRA_DIST = gpk.profile miocos-rw.profile pkcs15.profile

if HAVE_SSL
PROGRAMS_SSL = cryptoflex-tool pkcs15-init
endif

bin_PROGRAMS = opensc-tool opensc-explorer pkcs15-tool pkcs15-crypt \
	       $(PROGRAMS_SSL)

opensc_tool_SOURCES = opensc-tool.c util.c
opensc_tool_LDADD = @GETOPTSRC@
opensc_explorer_SOURCES = opensc-explorer.c util.c
opensc_explorer_LDADD = @GETOPTSRC@ @LIBREADLINE@
pkcs15_tool_SOURCES = pkcs15-tool.c util.c
pkcs15_tool_LDADD = @GETOPTSRC@
pkcs15_crypt_SOURCES = pkcs15-crypt.c util.c
pkcs15_crypt_LDADD = @GETOPTSRC@
cryptoflex_tool_SOURCES = cryptoflex-tool.c util.c
cryptoflex_tool_LDADD = @GETOPTSRC@ @LIBCRYPTO@
pkcs15_init_SOURCES = pkcs15-init.c profile.c util.c \
		      pkcs15-gpk.c pkcs15-miocos.c
pkcs15_init_LDADD = @GETOPTSRC@ @LIBCRYPTO@
noinst_HEADERS = util.h profile.h pkcs15-init.h
