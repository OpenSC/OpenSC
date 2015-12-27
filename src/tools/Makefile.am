include $(top_srcdir)/win32/ltrc.inc

MAINTAINERCLEANFILES = $(srcdir)/Makefile.in $(srcdir)/versioninfo-tools.rc
EXTRA_DIST = Makefile.mak versioninfo-tools.rc.in

noinst_HEADERS = util.h
bin_PROGRAMS = opensc-tool opensc-explorer pkcs15-tool pkcs15-crypt \
	pkcs11-tool cardos-tool eidenv openpgp-tool iasecc-tool
if ENABLE_OPENSSL
bin_PROGRAMS += cryptoflex-tool pkcs15-init netkey-tool piv-tool \
	westcos-tool sc-hsm-tool dnie-tool gids-tool
endif

# compile with $(PTHREAD_CFLAGS) to allow debugging with gdb
AM_CFLAGS = $(OPTIONAL_OPENSSL_CFLAGS) $(OPTIONAL_READLINE_CFLAGS) $(PTHREAD_CFLAGS)
AM_CPPFLAGS = -I$(top_srcdir)/src
LIBS = \
	$(top_builddir)/src/libopensc/libopensc.la \
	$(top_builddir)/src/common/libscdl.la \
	$(top_builddir)/src/common/libcompat.la

opensc_tool_SOURCES = opensc-tool.c util.c
piv_tool_SOURCES = piv-tool.c util.c
piv_tool_LDADD = $(OPTIONAL_OPENSSL_LIBS)
opensc_explorer_SOURCES = opensc-explorer.c util.c
opensc_explorer_LDADD = $(OPTIONAL_READLINE_LIBS)
pkcs15_tool_SOURCES = pkcs15-tool.c util.c
pkcs15_tool_LDADD = $(OPTIONAL_OPENSSL_LIBS)
pkcs11_tool_SOURCES = pkcs11-tool.c util.c
pkcs11_tool_LDADD = \
	$(top_builddir)/src/common/libpkcs11.la \
	$(OPTIONAL_OPENSSL_LIBS)
pkcs15_crypt_SOURCES = pkcs15-crypt.c util.c
pkcs15_crypt_LDADD = $(OPTIONAL_OPENSSL_LIBS)
cryptoflex_tool_SOURCES = cryptoflex-tool.c util.c
cryptoflex_tool_LDADD = $(OPTIONAL_OPENSSL_LIBS)
pkcs15_init_SOURCES = pkcs15-init.c util.c
pkcs15_init_LDADD = $(OPTIONAL_OPENSSL_LIBS)
cardos_tool_SOURCES = cardos-tool.c util.c
cardos_tool_LDADD = $(OPTIONAL_OPENSSL_LIBS)
eidenv_SOURCES = eidenv.c util.c
netkey_tool_SOURCES = netkey-tool.c
netkey_tool_LDADD = $(OPTIONAL_OPENSSL_LIBS)
westcos_tool_SOURCES = westcos-tool.c util.c
westcos_tool_LDADD = $(OPTIONAL_OPENSSL_LIBS)
openpgp_tool_SOURCES = openpgp-tool.c util.c
openpgp_tool_LDADD = $(OPTIONAL_OPENSSL_LIBS)
iasecc_tool_SOURCES = iasecc-tool.c util.c
iasecc_tool_LDADD = $(OPTIONAL_OPENSSL_LIBS)
sc_hsm_tool_SOURCES = sc-hsm-tool.c util.c
sc_hsm_tool_LDADD = $(OPTIONAL_OPENSSL_LIBS)
dnie_tool_SOURCES = dnie-tool.c util.c
dnie_tool_LDADD = $(OPTIONAL_OPENSSL_LIBS)
gids_tool_SOURCES = gids-tool.c util.c
gids_tool_LDADD = $(OPTIONAL_OPENSSL_LIBS)

if WIN32
opensc_tool_SOURCES += versioninfo-tools.rc
piv_tool_SOURCES += versioninfo-tools.rc
opensc_explorer_SOURCES += versioninfo-tools.rc
pkcs15_tool_SOURCES += versioninfo-tools.rc
pkcs11_tool_SOURCES += versioninfo-tools.rc
pkcs15_crypt_SOURCES += versioninfo-tools.rc
cryptoflex_tool_SOURCES += versioninfo-tools.rc
pkcs15_init_SOURCES += versioninfo-tools.rc
cardos_tool_SOURCES += versioninfo-tools.rc
eidenv_SOURCES += versioninfo-tools.rc
netkey_tool_SOURCES += versioninfo-tools.rc
westcos_tool_SOURCES += versioninfo-tools.rc
openpgp_tool_SOURCES += versioninfo-tools.rc
iasecc_tool_SOURCES += versioninfo-tools.rc
sc_hsm_tool_SOURCES += versioninfo-tools.rc
gids_tool_SOURCES += versioninfo-tools.rc
endif
