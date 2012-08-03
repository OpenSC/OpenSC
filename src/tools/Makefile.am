include $(top_srcdir)/win32/ltrc.inc

do_subst = $(SED) \
	   -e 's,[@]PACKAGE[@],$(PACKAGE),g' \
	   -e 's,[@]PACKAGE_NAME[@],$(PACKAGE_NAME),g' \
	   -e 's,[@]PACKAGE_TARNAME[@],$(PACKAGE_TARNAME),g' \
	   -e 's,[@]PACKAGE_BUGREPORT[@],$(PACKAGE_BUGREPORT),g' \
	   -e 's,[@]PACKAGE_URL[@],$(PACKAGE_URL),g' \
	   -e 's,[@]PACKAGE_VERSION[@],$(PACKAGE_VERSION),g'
BUILT_SOURCES = cmdline.h cmdline.c

MAINTAINERCLEANFILES = $(srcdir)/Makefile.in
MAINTAINERCLEANFILES += $(BUILT_SOURCES) npa-tool.ggo $(dist_man1_MANS)

EXTRA_DIST = Makefile.mak
EXTRA_DIST += npa-tool.ggo npa-tool.ggo.in

dist_man1_MANS		= npa-tool.1

noinst_HEADERS = util.h
bin_PROGRAMS = opensc-tool opensc-explorer pkcs15-tool pkcs15-crypt \
	pkcs11-tool cardos-tool eidenv openpgp-tool iasecc-tool
if ENABLE_OPENSSL
bin_PROGRAMS += cryptoflex-tool pkcs15-init netkey-tool piv-tool westcos-tool \
				npa-tool
endif

# compile with $(PTHREAD_CFLAGS) to allow debugging with gdb
AM_CFLAGS = $(OPTIONAL_OPENSSL_CFLAGS) $(OPTIONAL_READLINE_CFLAGS) $(PTHREAD_CFLAGS)
INCLUDES = -I$(top_srcdir)/src
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
npa_tool_SOURCES = npa-tool.c util.c $(BUILT_SOURCES)
npa_tool_LDADD = $(OPTIONAL_OPENSSL_LIBS)


npa-tool.c: $(BUILT_SOURCES)

$(BUILT_SOURCES): npa-tool.ggo
	$(GENGETOPT) --output-dir=$(srcdir) < $<

npa-tool.ggo: npa-tool.ggo.in
	$(do_subst) < $< > $(srcdir)/$@

npa-tool.1:
	$(HELP2MAN) \
		--output=$@ \
		--no-info \
		--source='$(PACKAGE_STRING)' \
		$(builddir)/npa-tool


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
westcos_tool_SOURCES += $(top_builddir)/win32/versioninfo.rc
openpgp_tool_SOURCES += $(top_builddir)/win32/versioninfo.rc
iasecc_tool_SOURCES += $(top_builddir)/win32/versioninfo.rc
endif
