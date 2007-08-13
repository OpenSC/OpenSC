# Process this file with automake to create Makefile.in

MAINTAINERCLEANFILES = Makefile.in

EXTRA_DIST = Makefile.mak

AM_CFLAGS = $(OPENSSL_CFLAGS) -I$(top_srcdir)/src/common
AM_LDFLAGS = @LIBOPENSC@

if HAVE_OPENSSL
PROGRAMS_OPENSSL = cryptoflex-tool pkcs15-init netkey-tool piv-tool 
endif

bin_PROGRAMS = opensc-tool opensc-explorer pkcs15-tool pkcs15-crypt \
	pkcs11-tool cardos-info eidenv \
	$(PROGRAMS_OPENSSL)

opensc_tool_SOURCES = opensc-tool.c util.c $(top_srcdir)/src/common/my_getopt.c
piv_tool_SOURCES = piv-tool.c util.c $(top_srcdir)/src/common/my_getopt.c
opensc_explorer_SOURCES = opensc-explorer.c util.c $(top_srcdir)/src/common/my_getopt.c
opensc_explorer_LDADD = $(LIBREADLINE)
pkcs15_tool_SOURCES = pkcs15-tool.c util.c $(top_srcdir)/src/common/my_getopt.c
pkcs15_tool_LDADD = $(OPENSSL_LIBS)
pkcs11_tool_SOURCES = pkcs11-tool.c util.c $(top_srcdir)/src/common/my_getopt.c
pkcs11_tool_LDADD = ../pkcs11/libpkcs11.la $(OPENSSL_LIBS)
pkcs15_crypt_SOURCES = pkcs15-crypt.c util.c $(top_srcdir)/src/common/my_getopt.c
pkcs15_crypt_LDADD = $(OPENSSL_LIBS)
cryptoflex_tool_SOURCES = cryptoflex-tool.c util.c $(top_srcdir)/src/common/my_getopt.c
cryptoflex_tool_LDADD = $(OPENSSL_LIBS)
pkcs15_init_SOURCES = pkcs15-init.c util.c $(top_srcdir)/src/common/my_getopt.c
pkcs15_init_LDADD = $(OPENSSL_LIBS) ../pkcs15init/libpkcs15init.la
cardos_info_SOURCES = cardos-info.c util.c $(top_srcdir)/src/common/my_getopt.c
eidenv_SOURCES = eidenv.c $(top_srcdir)/src/common/my_getopt.c
netkey_tool_SOURCES = netkey-tool.c $(top_srcdir)/src/common/my_getopt.c
netkey_tool_LDADD = $(OPENSSL_LIBS)

noinst_HEADERS = util.h
