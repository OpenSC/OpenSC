# Process this file with automake to create Makefile.in

includedir = @includedir@/opensc

MAINTAINERCLEANFILES = Makefile.in

EXTRA_DIST = Makefile.mak

noinst_LTLIBRARIES = libscrandom.la
libscrandom_la_SOURCES = scrandom.c scrandom.h

noinst_PROGRAMS = test-random

test_random_SOURCES = test-random.c
test_random_LDADD = libscrandom.la
