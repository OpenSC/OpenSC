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
TESTS_ENVIRONMENT = LD_PRELOAD='/usr/lib/x86_64-linux-gnu/libpcsclite.so.1'
endif

noinst_PROGRAMS = asn1 simpletlv cachedir pkcs15filter openpgp-tool hextobin \
	decode_ecdsa_signature check_macro_reference_loop strip_pkcs1_2_padding \
	base64
TESTS = asn1 simpletlv cachedir pkcs15filter openpgp-tool hextobin \
	decode_ecdsa_signature check_macro_reference_loop strip_pkcs1_2_padding \
	base64

noinst_HEADERS = torture.h

AM_CFLAGS = -I$(top_srcdir)/src/ \
	$(CODE_COVERAGE_CFLAGS) \
	$(OPTIONAL_OPENSSL_CFLAGS) \
	$(CMOCKA_CFLAGS)
AM_CPPFLAGS =$(CODE_COVERAGE_CPPFLAGS)
LDADD = $(top_builddir)/src/libopensc/libopensc.la \
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
