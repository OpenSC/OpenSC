MAINTAINERCLEANFILES = $(srcdir)/Makefile.in
EXTRA_DIST = Makefile.mak

if ENABLE_CMOCKA
include $(top_srcdir)/aminclude_static.am
clean-local: code-coverage-clean
distclean-local: code-coverage-dist-clean

@VALGRIND_CHECK_RULES@
if VALGRIND_ENABLED
#VALGRIND_SUPPRESSIONS_FILES = $(top_srcdir)/tests/opensc.supp
VALGRIND_FLAGS = --num-callers=30 -q --keep-debuginfo=yes --gen-suppressions=all
# to avoid false positive leaks from pcsclite
TESTS_ENVIRONMENT = LD_PRELOAD='$(PCSCLITE_PATH)'
endif

noinst_PROGRAMS = asn1 simpletlv cachedir pkcs15filter openpgp-tool hextobin \
	decode_ecdsa_signature check_macro_reference_loop strip_pkcs1_2_padding \
	base64 parse_pkcs11_uri pkcs15-tlv-record pkcs11-pss-params epki-research epki-lifecycle \
	pkcs11-find-objects pkcs11-discovery
TESTS = asn1 simpletlv cachedir pkcs15filter openpgp-tool hextobin \
	decode_ecdsa_signature check_macro_reference_loop strip_pkcs1_2_padding \
	base64 parse_pkcs11_uri pkcs15-tlv-record pkcs11-pss-params epki-research epki-lifecycle \
	pkcs11-find-objects pkcs11-discovery

noinst_HEADERS = torture.h

AM_CFLAGS = -I$(top_srcdir)/src/ \
	$(CODE_COVERAGE_CFLAGS) \
	$(OPTIONAL_OPENSSL_CFLAGS) \
	$(CMOCKA_CFLAGS)
AM_CPPFLAGS =$(CODE_COVERAGE_CPPFLAGS)
LDADD = $(top_builddir)/src/libopensc/libopensc.la \
	$(top_builddir)/src/common/libscdl.la \
	$(top_builddir)/src/common/libcompat.la \
	$(CODE_COVERAGE_LIBS) \
	$(OPTIONAL_OPENSSL_LIBS) \
	$(CMOCKA_LIBS)

asn1_SOURCES = asn1.c
simpletlv_SOURCES = simpletlv.c
cachedir_SOURCES = cachedir.c
pkcs15filter_SOURCES = pkcs15-emulator-filter.c
openpgp_tool_SOURCES = openpgp-tool.c $(top_builddir)/src/tools/openpgp-tool-helpers.c
hextobin_SOURCES = hextobin.c
decode_ecdsa_signature_SOURCES = decode_ecdsa_signature.c
check_macro_reference_loop_SOURCES = check_macro_reference_loop.c
strip_pkcs1_2_padding_SOURCES = strip_pkcs1_2_padding.c
base64_SOURCES = base64.c
parse_pkcs11_uri_SOURCES = parse_pkcs11_uri.c
pkcs15_tlv_record_SOURCES = pkcs15-tlv-record.c
pkcs11_pss_params_SOURCES = pkcs11-pss-params.c
epki_research_SOURCES = epki-research.c
epki_lifecycle_SOURCES = epki-lifecycle.c
pkcs11_find_objects_SOURCES = pkcs11-find-objects.c
pkcs11_discovery_SOURCES = pkcs11-discovery.c
pkcs11_find_objects_LDADD = $(top_builddir)/src/pkcs11/libopensc-pkcs11.la $(LDADD)
pkcs11_discovery_LDADD = $(top_builddir)/src/pkcs11/libopensc-pkcs11.la $(LDADD)
pkcs11_discovery_CFLAGS = $(AM_CFLAGS) $(OPENPACE_CFLAGS) $(OPENSC_PKCS11_PTHREAD_CFLAGS)

if ENABLE_ZLIB
noinst_PROGRAMS += compression
TESTS += compression

compression_SOURCES = compression.c
compression_LDADD = $(LDADD) $(OPTIONAL_ZLIB_LIBS)
endif

if ENABLE_OPENSSL
noinst_PROGRAMS += sm
TESTS += sm

sm_SOURCES = sm.c
sm_LDADD = $(top_builddir)/src/sm/libsm.la $(LDADD)
endif


endif
