MAINTAINERCLEANFILES = $(srcdir)/Makefile.in
EXTRA_DIST = Makefile.mak

if ENABLE_CMOCKA
noinst_PROGRAMS = asn1

noinst_HEADERS = torture.h

AM_CPPFLAGS = -I$(top_srcdir)/src/ -Lopensc

asn1_SOURCES = asn1.c
asn1_CFLAGS = $(CMOCKA_CFLAGS)
asn1_LDADD = $(top_builddir)/src/libopensc/libopensc.la $(CMOCKA_LIBS) $(OPTIONAL_OPENSSL_LIBS)


TESTS = asn1
endif
