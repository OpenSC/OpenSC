# Process this file with automake to create Makefile.in

include_HEADERS = scrandom.h

lib_LTLIBRARIES = libscrandom.la

if HAVE_SSL
SSL_LTLIB = @LIBCRYPTO@
else
SSL_LTLIB = 
endif

libscrandom_la_SOURCES = scrandom.c scrandom.h
libscrandom_la_LIBADD = $(SSL_LTLIB)

test_random_SOURCES = test-random.c
test_random_LDFLAGS = @LDFLAGS@ @LIBSCRANDOM@
