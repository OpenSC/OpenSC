# Process this file with automake to create Makefile.in

includedir = ${prefix}/include/opensc

MAINTAINERCLEANFILES = Makefile.in

EXTRA_DIST = Makefile.mak

include_HEADERS = scrandom.h

if HAVE_SSL
SSL_LIB = @LIBCRYPTO@
endif

# lib_LTLIBRARIES = libscrandom.la

noinst_PROGRAMS = test-random

test_random_SOURCES = test-random.c scrandom.c scrandom.h
test_random_LDFLAGS = @LDFLAGS@ $(SSL_LIB)
