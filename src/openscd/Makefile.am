# Process this file with automake to create Makefile.in

MAINTAINERCLEANFILES = Makefile.in

EXTRA_DIST = test.c

INCLUDES = @CPPFLAGS@ @CFLAGS_ASSUAN@
LDFLAGS = @LDFLAGS@ @LIBOPENSC@

if HAVE_ASSUAN
noinst_PROGRAMS = openscd
endif

openscd_SOURCES = openscd.c commands.c mkdtemp.c openscd.h
openscd_LDADD = @GETOPTSRC@ @LIBASSUAN@ ../scrandom/libscrandom.la
