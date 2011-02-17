include $(top_srcdir)/win32/ltrc.inc

MAINTAINERCLEANFILES = $(srcdir)/Makefile.in
EXTRA_DIST = Makefile.mak

noinst_HEADERS = util.h
bin_PROGRAMS = opensc-tool opensc-explorer pkcs15-tool pkcs15-crypt \
 	pkcs11-tool cardos-tool eidenv rutoken-tool
if ENABLE_OPENSSL
bin_PROGRAMS += cryptoflex-tool pkcs15-init netkey-tool piv-tool westcos-tool
endif

# compile with $(PTHREAD_CFLAGS) to allow debugging with gdb
AM_CFLAGS = $(OPTIONAL_OPENSSL_CFLAGS) $(OPTIONAL_READLINE_CFLAGS) $(PTHREAD_CFLAGS)
INCLUDES = -I$(top_srcdir)/src
LIBS = $(top_builddir)/src/common/libcompat.la \
	$(top_builddir)/src/libopensc/libopensc.la

opensc_tool_SOURCES = opensc-tool.c util.c
piv_tool_SOURCES = piv-tool.c util.c
piv_tool_LDADD = $(OPTIONAL_OPENSSL_LIBS)
opensc_explorer_SOURCES = opensc-explorer.c util.c
opensc_explorer_LDADD = $(OPTIONAL_READLINE_LIBS)
pkcs15_tool_SOURCES = pkcs15-tool.c util.c
pkcs15_tool_LDADD = $(OPTIONAL_OPENSSL_LIBS)
pkcs11_tool_SOURCES = pkcs11-tool.c util.c
pkcs11_tool_LDADD = $(OPTIONAL_OPENSSL_LIBS) $(LTLIB_LIBS) \
	$(top_builddir)/src/common/libpkcs11.la
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
rutoken_tool_SOURCES = rutoken-tool.c util.c
rutoken_tool_LDADD = $(OPTIONAL_OPENSSL_LIBS)
westcos_tool_SOURCES = westcos-tool.c util.c
westcos_tool_LDADD = $(OPTIONAL_OPENSSL_LIBS)

if WIN32
opensc_tool_SOURCES += $(top_builddir)/win32/versioninfo.rc
piv_tool_SOURCES += $(top_builddir)/win32/versioninfo.rc
opensc_explorer_SOURCES += $(top_builddir)/win32/versioninfo.rc
pkcs15_tool_SOURCES += $(top_builddir)/win32/versioninfo.rc
pkcs11_tool_SOURCES += $(top_builddir)/win32/versioninfo.rc
pkcs15_crypt_SOURCES += $(top_builddir)/win32/versioninfo.rc
cryptoflex_tool_SOURCES += $(top_builddir)/win32/versioninfo.rc
pkcs15_init_SOURCES += $(top_builddir)/win32/versioninfo.rc
cardos_tool_SOURCES += $(top_builddir)/win32/versioninfo.rc
eidenv_SOURCES += $(top_builddir)/win32/versioninfo.rc
netkey_tool_SOURCES += $(top_builddir)/win32/versioninfo.rc
rutoken_tool_SOURCES += $(top_builddir)/win32/versioninfo.rc
westcos_tool_SOURCES += $(top_builddir)/win32/versioninfo.rc
endif
