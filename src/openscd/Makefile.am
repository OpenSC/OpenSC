# Process this file with automake to create Makefile.in

MAINTAINERCLEANFILES = Makefile.in

EXTRA_DIST = test.c

INCLUDES = @CFLAGS_OPENSC@
LDFLAGS = @LDFLAGS@ @LIBOPENSC@

noinst_PROGRAMS = openscd

openscd_SOURCES = openscd.c commands.c mkdtemp.c openscd.h
openscd_LDADD = @GETOPTSRC@ ../assuan/libassuan.la ../scrandom/libscrandom.la
