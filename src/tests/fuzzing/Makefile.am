AM_CPPFLAGS = -I$(top_srcdir)/src
AM_CFLAGS = -g -O0 $(OPTIONAL_OPENSSL_CFLAGS) $(OPTIONAL_READLINE_CFLAGS) $(PTHREAD_CFLAGS)
LIBS = $(FUZZING_LIBS)\
	$(top_builddir)/src/libopensc/libopensc.la \
	$(top_builddir)/src/common/libscdl.la \
	$(top_builddir)/src/common/libcompat.la

noinst_PROGRAMS = fuzz_asn1_print fuzz_asn1_sig_value fuzz_pkcs15_decode fuzz_pkcs15_reader \
					fuzz_scconf_parse_string	

ADDITIONAL_SRC =
if !ENABLE_FUZZING
ADDITIONAL_SRC += fuzzer.c
endif

fuzz_asn1_print_SOURCES = fuzz_asn1_print.c $(ADDITIONAL_SRC)
fuzz_asn1_sig_value_SOURCES = fuzz_asn1_sig_value.c $(ADDITIONAL_SRC)
fuzz_pkcs15_decode_SOURCES = fuzz_pkcs15_decode.c $(ADDITIONAL_SRC)
fuzz_pkcs15_reader_SOURCES = fuzz_pkcs15_reader.c $(ADDITIONAL_SRC)
fuzz_scconf_parse_string_SOURCES = fuzz_scconf_parse_string.c $(ADDITIONAL_SRC)
