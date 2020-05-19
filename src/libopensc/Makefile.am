include $(top_srcdir)/win32/ltrc.inc

MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

EXTRA_DIST = Makefile.mak opensc.dll.manifest

lib_LTLIBRARIES = libopensc.la
noinst_HEADERS = cards.h ctbcs.h internal.h muscle.h muscle-filesystem.h \
	internal-winscard.h p15card-helper.h pkcs15-syn.h \
	opensc.h pkcs15.h gp.h \
	cardctl.h asn1.h log.h simpletlv.h \
	errors.h types.h compression.h itacns.h iso7816.h \
	authentic.h iasecc.h iasecc-sdo.h sm.h card-sc-hsm.h \
	pace.h cwa14890.h cwa-dnie.h card-gids.h aux-data.h \
	jpki.h sc-ossl-compat.h card-npa.h card-openpgp.h \
	ccid-types.h reader-tr03119.h \
	card-cac-common.h

AM_CPPFLAGS = -D'OPENSC_CONF_PATH="$(sysconfdir)/opensc.conf"' \
     -D'DEFAULT_SM_MODULE_PATH="$(DEFAULT_SM_MODULE_PATH)"' \
     -D'DEFAULT_SM_MODULE="$(DEFAULT_SM_MODULE)"' \
	-I$(top_srcdir)/src
AM_CFLAGS = $(OPENPACE_CFLAGS) $(OPTIONAL_OPENSSL_CFLAGS) $(OPTIONAL_OPENCT_CFLAGS) \
	$(OPTIONAL_PCSC_CFLAGS) $(OPTIONAL_ZLIB_CFLAGS)
AM_OBJCFLAGS = $(AM_CFLAGS)

libopensc_la_SOURCES_BASE = \
	sc.c ctx.c log.c errors.c \
	asn1.c base64.c sec.c card.c iso7816.c dir.c ef-atr.c \
	ef-gdo.c padding.c apdu.c simpletlv.c gp.c \
	\
	pkcs15.c pkcs15-cert.c pkcs15-data.c pkcs15-pin.c \
	pkcs15-prkey.c pkcs15-pubkey.c pkcs15-skey.c \
	pkcs15-sec.c pkcs15-algo.c pkcs15-cache.c pkcs15-syn.c \
	\
	muscle.c muscle-filesystem.c \
	\
	ctbcs.c reader-ctapi.c reader-pcsc.c reader-openct.c reader-tr03119.c \
	\
	card-setcos.c card-miocos.c card-flex.c card-gpk.c \
	card-cardos.c card-tcos.c card-default.c \
	card-mcrd.c card-starcos.c card-openpgp.c card-jcop.c \
	card-oberthur.c card-belpic.c card-atrust-acos.c \
	card-entersafe.c card-epass2003.c card-coolkey.c card-incrypto34.c \
	card-piv.c card-cac-common.c card-cac.c card-cac1.c \
	card-muscle.c card-asepcos.c card-akis.c card-gemsafeV1.c card-rutoken.c \
	card-rtecp.c card-westcos.c card-myeid.c \
	card-itacns.c card-authentic.c \
	card-iasecc.c iasecc-sdo.c iasecc-sm.c card-sc-hsm.c \
	card-dnie.c cwa14890.c cwa-dnie.c \
	card-isoApplet.c card-masktech.c card-gids.c card-jpki.c \
	card-npa.c card-esteid2018.c card-idprime.c \
	card-edo.c \
	\
	pkcs15-openpgp.c pkcs15-starcert.c pkcs15-cardos.c \
	pkcs15-tcos.c pkcs15-esteid.c pkcs15-gemsafeGPK.c \
	pkcs15-actalis.c pkcs15-atrust-acos.c pkcs15-tccardos.c pkcs15-piv.c \
	pkcs15-cac.c pkcs15-esinit.c pkcs15-westcos.c pkcs15-pteid.c \
	pkcs15-oberthur.c pkcs15-itacns.c pkcs15-gemsafeV1.c pkcs15-sc-hsm.c \
	pkcs15-coolkey.c pkcs15-din-66291.c pkcs15-idprime.c \
	pkcs15-dnie.c pkcs15-gids.c pkcs15-iasecc.c pkcs15-jpki.c pkcs15-esteid2018.c \
	compression.c p15card-helper.c sm.c \
	aux-data.c

if ENABLE_CRYPTOTOKENKIT
# most platforms don't support objective C the way we needed.
# Only include it if needed
libopensc_la_SOURCES_BASE += reader-cryptotokenkit.m
endif
libopensc_la_LIBTOOLFLAGS = --tag CC
libopensc_static_la_LIBTOOLFLAGS = --tag CC

libopensc_la_SOURCES = $(libopensc_la_SOURCES_BASE) \
	libopensc.exports
libopensc_static_la_SOURCES = $(libopensc_la_SOURCES_BASE)

if WIN32
libopensc_la_SOURCES += $(top_builddir)/win32/versioninfo.rc
endif
libopensc_la_LIBADD = $(OPENPACE_LIBS) $(OPTIONAL_OPENSSL_LIBS) \
	$(OPTIONAL_OPENCT_LIBS) $(OPTIONAL_ZLIB_LIBS) \
	$(top_builddir)/src/pkcs15init/libpkcs15init.la \
	$(top_builddir)/src/scconf/libscconf.la \
	$(top_builddir)/src/common/libscdl.la \
	$(top_builddir)/src/ui/libnotify.la \
	$(top_builddir)/src/ui/libstrings.la \
	$(top_builddir)/src/sm/libsmeac.la \
	$(top_builddir)/src/common/libcompat.la
if WIN32
libopensc_la_LIBADD += -lws2_32
endif
libopensc_static_la_LIBADD = $(libopensc_la_LIBADD)
libopensc_la_LDFLAGS = $(AM_LDFLAGS) \
	-version-info @OPENSC_LT_CURRENT@:@OPENSC_LT_REVISION@:@OPENSC_LT_AGE@ \
	-export-symbols "$(srcdir)/libopensc.exports" \
	-no-undefined

if WIN32
# def file required for MS users to build library
mylibdir=$(libdir)
mylib_DATA=.libs/@WIN_LIBPREFIX@opensc-@OPENSC_LT_OLDEST@.dll.def
.libs/@WIN_LIBPREFIX@opensc-@OPENSC_LT_OLDEST@.dll.def:	libopensc.la

if ENABLE_MINIDRIVER
noinst_LTLIBRARIES = libopensc_static.la
endif
endif

TIDY_FLAGS = $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(CPPFLAGS) $(AM_CFLAGS) $(CFLAGS)
TIDY_FILES = \
	sc.c ctx.c errors.c \
	asn1.c base64.c sec.c card.c iso7816.c dir.c ef-atr.c \
	ef-gdo.c padding.c apdu.c simpletlv.c gp.c \
	\
	pkcs15-cert.c pkcs15-data.c pkcs15-pin.c \
	pkcs15-prkey.c pkcs15-pubkey.c pkcs15-skey.c \
	pkcs15-sec.c pkcs15-algo.c pkcs15-cache.c pkcs15-syn.c \
	\
	muscle.c muscle-filesystem.c \
	\
	ctbcs.c reader-ctapi.c reader-pcsc.c reader-openct.c reader-tr03119.c \
	\
	card-setcos.c card-miocos.c card-flex.c card-gpk.c \
	card-cardos.c card-tcos.c card-default.c \
	card-mcrd.c card-starcos.c card-jcop.c \
	card-oberthur.c card-belpic.c card-atrust-acos.c \
	card-entersafe.c card-epass2003.c card-coolkey.c card-incrypto34.c \
	card-cac-common.c card-cac.c card-cac1.c \
	card-muscle.c card-asepcos.c card-akis.c card-gemsafeV1.c card-rutoken.c \
	card-rtecp.c card-westcos.c card-myeid.c \
	card-itacns.c card-authentic.c \
	card-iasecc.c iasecc-sdo.c iasecc-sm.c card-sc-hsm.c \
	cwa14890.c cwa-dnie.c \
	card-isoApplet.c card-masktech.c card-jpki.c \
	card-npa.c card-esteid2018.c card-idprime.c \
	card-edo.c \
	\
	pkcs15-openpgp.c pkcs15-cardos.c \
	pkcs15-tcos.c pkcs15-esteid.c \
	pkcs15-actalis.c pkcs15-atrust-acos.c pkcs15-tccardos.c \
	pkcs15-cac.c pkcs15-esinit.c pkcs15-westcos.c pkcs15-pteid.c \
	pkcs15-oberthur.c pkcs15-itacns.c pkcs15-sc-hsm.c \
	pkcs15-coolkey.c pkcs15-din-66291.c pkcs15-idprime.c \
	pkcs15-dnie.c pkcs15-gids.c pkcs15-iasecc.c pkcs15-jpki.c pkcs15-esteid2018.c \
	compression.c p15card-helper.c sm.c \
	aux-data.c \
	#$(SOURCES)

check-local:
	if [ -x "$(CLANGTIDY)" ]; then clang-tidy -config='' -header-filter=.* $(TIDY_FILES) -- $(TIDY_FLAGS); fi
