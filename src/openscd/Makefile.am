# Process this file with automake to create Makefile.in

MAINTAINERCLEANFILES = Makefile.in

INCLUDES = @CFLAGS_OPENSC@
AM_LDFLAGS = @LDFLAGS@ @LIBOPENSC@

bin_PROGRAMS = openscd

openscd_SOURCES = openscd.c commands.c mkdtemp.c
openscd_LDADD = @GETOPTSRC@ ../assuan/libassuan.a ../scrandom/libscrandom.a
