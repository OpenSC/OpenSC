include $(top_srcdir)/win32/ltrc.inc

if ENABLE_ZLIB
VDFORMAT=XML
else
VDFORMAT=GZIP
endif

do_subst = $(SED) \
	   -e 's,[@]bindir[@],$(bindir),g' \
	   -e 's,[@]CVCDIR[@],$(CVCDIR),g' \
	   -e 's,[@]PACKAGE[@],$(PACKAGE),g' \
	   -e 's,[@]PACKAGE_BUGREPORT[@],$(PACKAGE_BUGREPORT),g' \
	   -e 's,[@]PACKAGE_NAME[@],$(PACKAGE_NAME),g' \
	   -e 's,[@]PACKAGE_TARNAME[@],$(PACKAGE_TARNAME),g' \
	   -e 's,[@]PACKAGE_URL[@],$(PACKAGE_URL),g' \
	   -e 's,[@]PACKAGE_SUMMARY[@],$(PACKAGE_SUMMARY),g' \
	   -e 's,[@]PACKAGE_VERSION[@],"$(PACKAGE_VERSION)",g' \
	   -e 's,[@]VDFORMAT[@],$(VDFORMAT),g' \
	   -e 's,[@]X509DIR[@],$(X509DIR),g'

MAINTAINERCLEANFILES = $(srcdir)/Makefile.in $(srcdir)/versioninfo-tools.rc $(srcdir)/versioninfo-opensc-notify.rc
EXTRA_DIST = Makefile.mak versioninfo-tools.rc.in versioninfo-opensc-notify.rc.in goid-tool.ggo.in npa-tool.ggo.in opensc-notify.ggo.in egk-tool.ggo.in opensc-asn1.ggo.in org.opensc.notify.desktop.in exe.manifest

noinst_HEADERS = util.h fread_to_eof.h \
	egk-tool-cmdline.h goid-tool-cmdline.h npa-tool-cmdline.h \
	opensc-asn1-cmdline.h opensc-notify-cmdline.h
noinst_PROGRAMS = sceac-example
bin_PROGRAMS = opensc-tool opensc-explorer opensc-notify \
	pkcs15-tool pkcs15-crypt pkcs11-tool \
	cardos-tool eidenv openpgp-tool iasecc-tool egk-tool opensc-asn1 goid-tool
if ENABLE_OPENSSL
bin_PROGRAMS += cryptoflex-tool pkcs15-init netkey-tool piv-tool \
	westcos-tool sc-hsm-tool dnie-tool gids-tool npa-tool
endif

# compile with $(PTHREAD_CFLAGS) to allow debugging with gdb
AM_CFLAGS = $(OPTIONAL_OPENSSL_CFLAGS) $(OPTIONAL_READLINE_CFLAGS) $(PTHREAD_CFLAGS)
AM_CPPFLAGS = -I$(top_srcdir)/src -D'DEFAULT_PKCS11_PROVIDER="$(DEFAULT_PKCS11_PROVIDER)"'
LIBS = \
	$(top_builddir)/src/libopensc/libopensc.la \
	$(top_builddir)/src/common/libscdl.la \
	$(top_builddir)/src/common/libcompat.la

sceac_example_SOURCES = sceac-example.c
sceac_example_LDADD = $(top_builddir)/src/libopensc/libopensc.la $(OPENPACE_LIBS)
sceac_example_CFLAGS = -I$(top_srcdir)/src $(OPENPACE_CFLAGS)

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
if ENABLE_SHARED
else
pkcs11_tool_LDADD += \
	$(top_builddir)/src/pkcs11/libopensc-pkcs11.la
endif
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

npa_tool_SOURCES = npa-tool.c fread_to_eof.c util.c npa-tool-cmdline.c
npa_tool_LDADD = $(top_builddir)/src/libopensc/libopensc.la \
				 $(OPENPACE_LIBS)
npa_tool_CFLAGS = -I$(top_srcdir)/src $(OPENPACE_CFLAGS) $(OPENSSL_CFLAGS)
npa_tool_CFLAGS += -Wno-unused-but-set-variable
if HAVE_UNKNOWN_WARNING_OPTION
npa_tool_CFLAGS += -Wno-unknown-warning-option
endif

opensc_notify_SOURCES = opensc-notify.c opensc-notify-cmdline.c
opensc_notify_LDADD = $(top_builddir)/src/libopensc/libopensc.la $(OPTIONAL_NOTIFY_LIBS)
opensc_notify_CFLAGS = -I$(top_srcdir)/src $(OPTIONAL_NOTIFY_CFLAGS)
opensc_notify_CFLAGS += -Wno-unused-but-set-variable
if HAVE_UNKNOWN_WARNING_OPTION
opensc_notify_CFLAGS += -Wno-unknown-warning-option
endif

egk_tool_SOURCES = egk-tool.c util.c egk-tool-cmdline.c
egk_tool_LDADD = $(top_builddir)/src/libopensc/libopensc.la $(OPTIONAL_ZLIB_LIBS)
egk_tool_CFLAGS = -I$(top_srcdir)/src $(OPTIONAL_ZLIB_CFLAGS)
egk_tool_CFLAGS += -Wno-unused-but-set-variable
if HAVE_UNKNOWN_WARNING_OPTION
egk_tool_CFLAGS += -Wno-unknown-warning-option
endif

goid_tool_SOURCES = goid-tool.c util.c fread_to_eof.c goid-tool-cmdline.c
goid_tool_LDADD = $(top_builddir)/src/libopensc/libopensc.la $(OPENPACE_LIBS)
goid_tool_CFLAGS = -I$(top_srcdir)/src $(OPENPACE_CFLAGS)
goid_tool_CFLAGS += -Wno-unused-but-set-variable
if HAVE_UNKNOWN_WARNING_OPTION
goid_tool_CFLAGS += -Wno-unknown-warning-option
endif

opensc_asn1_SOURCES = opensc-asn1.c fread_to_eof.c opensc-asn1-cmdline.c
opensc_asn1_LDADD = $(top_builddir)/src/libopensc/libopensc.la $(OPTIONAL_ZLIB_LIBS)
opensc_asn1_CFLAGS = -I$(top_srcdir)/src $(OPTIONAL_ZLIB_CFLAGS)
opensc_asn1_CFLAGS += -Wno-unused-but-set-variable
if HAVE_UNKNOWN_WARNING_OPTION
opensc_asn1_CFLAGS += -Wno-unknown-warning-option
endif

.PHONY: cmdline
cmdline:
	for f in *.ggo.in; do $(do_subst) < "$$f" > "$${f%.in}"; done
	for f in *.ggo;    do $(GENGETOPT) --file-name="$${f%.ggo}-cmdline" --output-dir=$(builddir) < "$$f"; done
	$(GENGETOPT) --file-name=opensc-asn1-cmdline --output-dir=$(builddir) < opensc-asn1.ggo --unamed-opts

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
opensc_notify_SOURCES += versioninfo-opensc-notify.rc
endif

applicationsdir = $(datadir)/applications
applications_DATA = org.opensc.notify.desktop

org.opensc.notify.desktop: org.opensc.notify.desktop.in
	$(do_subst) < $(abs_srcdir)/org.opensc.notify.desktop.in > $@

clean-local:
	rm -f $(abs_builddir)/npa-tool.ggo $(abs_builddir)/opensc-notify.ggo $(abs_builddir)/opensc-asn1.ggo $(abs_builddir)/goid-tool.ggo $(abs_builddir)/egk-tool.ggo org.opensc.notify.desktop
