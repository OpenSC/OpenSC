# Process this file with automake to create Makefile.in

includedir = ${prefix}/include/opensc

MAINTAINERCLEANFILES = Makefile.in lex-parse.c

EXTRA_DIST = Makefile.am

include_HEADERS = scconf.h
noinst_HEADERS = internal.h

lib_LTLIBRARIES = libscconf.la
libscconf_la_SOURCES = scconf.c parse.c write.c lex-parse.l

noinst_PROGRAMS = test-conf

test_conf_SOURCES = test-conf.c
test_conf_LDFLAGS = @LDFLAGS@ libscconf.la
