# Process this file with automake to create Makefile.in

includedir = ${prefix}/include/opensc

MAINTAINERCLEANFILES = Makefile.in

EXTRA_DIST = Makefile.mak

if HAVE_SSL
SSL_LIB = @LIBCRYPTO@
endif

noinst_LTLIBRARIES = libscrandom.la
libscrandom_la_SOURCES = scrandom.c scrandom.h

noinst_PROGRAMS = test-random

test_random_SOURCES = test-random.c
test_random_LDADD = $(SSL_LIB) libscrandom.la
