MAINTAINERCLEANFILES = $(srcdir)/Makefile.in
EXTRA_DIST = Makefile.mak

if ENABLE_CMOCKA
include $(top_srcdir)/aminclude_static.am
clean-local: code-coverage-clean
distclean-local: code-coverage-dist-clean

noinst_PROGRAMS = asn1 simpletlv
TESTS = asn1 simpletlv

noinst_HEADERS = torture.h

AM_CFLAGS = -I$(top_srcdir)/src/ \
	$(CODE_COVERAGE_CFLAGS) \
	$(CMOCKA_CFLAGS)
AM_CPPFLAGS =$(CODE_COVERAGE_CPPFLAGS)
LDADD = $(top_builddir)/src/libopensc/libopensc.la \
	$(CODE_COVERAGE_LIBS) \
	$(OPTIONAL_OPENSSL_LIBS) \
	$(CMOCKA_LIBS)

asn1_SOURCES = asn1.c
simpletlv_SOURCES = simpletlv.c

if ENABLE_ZLIB
noinst_PROGRAMS += compression
TESTS += compression

compression_SOURCES = compression.c
compression_LDADD = $(LDADD) $(OPTIONAL_ZLIB_LIBS)
endif



endif
