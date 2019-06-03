AM_CPPFLAGS = -I$(top_srcdir)/src
AM_CFLAGS = -g -O0 $(OPTIONAL_OPENSSL_CFLAGS) $(OPTIONAL_READLINE_CFLAGS) $(PTHREAD_CFLAGS)
LIBS = \
	$(top_builddir)/src/libopensc/libopensc.la \
	$(top_builddir)/src/common/libscdl.la \
	$(top_builddir)/src/common/libcompat.la

if ENABLE_FUZZING
noinst_PROGRAMS = fuzz_asn1_print fuzz_asn1_sig_value fuzz_pkcs15_decode fuzz_pkcs15_reader
endif

fuzz_asn1_print_SOURCES = fuzz_asn1_print.c
fuzz_asn1_sig_value_SOURCES = fuzz_asn1_sig_value.c
fuzz_pkcs15_decode_SOURCES = fuzz_pkcs15_decode.c
fuzz_pkcs15_reader_SOURCES = fuzz_pkcs15_reader.c
