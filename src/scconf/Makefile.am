# Process this file with automake to create Makefile.in

includedir = @includedir@/opensc

MAINTAINERCLEANFILES = Makefile.in lex-parse.c

EXTRA_DIST = Makefile.mak

include_HEADERS = scconf.h
noinst_HEADERS = internal.h

lib_LTLIBRARIES = libscconf.la
libscconf_la_SOURCES = scconf.c parse.c write.c lex-parse.l
libscconf_la_LDFLAGS = -version-info @OPENSC_LT_CURRENT@:@OPENSC_LT_REVISION@:@OPENSC_LT_AGE@

noinst_PROGRAMS = test-conf

test_conf_SOURCES = test-conf.c
test_conf_LDFLAGS = @LDFLAGS@ libscconf.la
