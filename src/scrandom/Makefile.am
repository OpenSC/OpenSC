# Process this file with automake to create Makefile.in

includedir = ${prefix}/include/opensc

MAINTAINERCLEANFILES = Makefile.in

include_HEADERS = scrandom.h

if HAVE_SSL
SSL_LTLIB = @LIBCRYPTO@
endif

lib_LTLIBRARIES = libscrandom.la

libscrandom_la_SOURCES = scrandom.c scrandom.h
libscrandom_la_LIBADD = $(SSL_LTLIB)

noinst_PROGRAMS = test-random

test_random_SOURCES = test-random.c
test_random_LDFLAGS = @LDFLAGS@ @LIBSCRANDOM@
