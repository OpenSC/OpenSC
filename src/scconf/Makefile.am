# Process this file with automake to create Makefile.in

MAINTAINERCLEANFILES = Makefile.in lex-parse.c

include_HEADERS = scconf.h
noinst_HEADERS = internal.h

lib_LTLIBRARIES = libscconf.la
libscconf_la_SOURCES = scconf.c parse.c write.c lex-parse.l

noinst_PROGRAMS = test-conf

test_conf_SOURCES = test-conf.c
test_conf_LDFLAGS = @LDFLAGS@ libscconf.la
