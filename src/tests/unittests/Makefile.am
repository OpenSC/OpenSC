MAINTAINERCLEANFILES = $(srcdir)/Makefile.in
EXTRA_DIST = Makefile.mak

if ENABLE_CMOCKA
include $(top_srcdir)/aminclude_static.am
clean-local: code-coverage-clean
distclean-local: code-coverage-dist-clean

noinst_PROGRAMS = asn1

noinst_HEADERS = torture.h

AM_CPPFLAGS = -I$(top_srcdir)/src/ -Lopensc $(CODE_COVERAGE_CPPFLAGS)

asn1_SOURCES = asn1.c
asn1_CFLAGS = $(CMOCKA_CFLAGS) $(CODE_COVERAGE_CFLAGS)
asn1_LDADD = $(top_builddir)/src/libopensc/libopensc.la \
	$(CMOCKA_LIBS) $(CODE_COVERAGE_LIBS) $(OPTIONAL_OPENSSL_LIBS)


TESTS = asn1

endif
