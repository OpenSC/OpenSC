# Process this file with automake to create Makefile.in

include_HEADERS = scrandom.h

if HAVE_SSL
SSL_LTLIB = @LIBCRYPTO@
else
SSL_LTLIB = 
endif

lib_LTLIBRARIES = libscrandom.la

libscrandom_la_SOURCES = scrandom.c scrandom.h
libscrandom_la_LIBADD = $(SSL_LTLIB)

noinst_PROGRAMS = test-random

test_random_SOURCES = test-random.c
test_random_LDFLAGS = @LDFLAGS@ @LIBSCRANDOM@
