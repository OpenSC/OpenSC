# Process this file with automake to create Makefile.in

includedir = ${prefix}/include/opensc

MAINTAINERCLEANFILES = Makefile.in

EXTRA_DIST = Makefile.mak

include_HEADERS = scrandom.h

if HAVE_SSL
SSL_LIB = @LIBCRYPTO@
endif

lib_LIBRARIES = libscrandom.a

libscrandom_a_SOURCES = scrandom.c scrandom.h

noinst_PROGRAMS = test-random

test_random_SOURCES = test-random.c
test_random_LDFLAGS = @LDFLAGS@ @LIBSCRANDOM@ $(SSL_LIB)
