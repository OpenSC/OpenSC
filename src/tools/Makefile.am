# Process this file with automake to create Makefile.in

INCLUDES = @CFLAGS_PCSC@ @CFLAGS_OPENSC@
LDFLAGS = @LDFLAGS@ @LIBOPENSC@

bin_PROGRAMS = opensc-crypt opensc-tool

opensc_crypt_SOURCES = opensc-crypt.c util.c
opensc_crypt_LDADD = @GETOPTSRC@
opensc_tool_SOURCES = opensc-tool.c util.c
opensc_tool_LDADD = @GETOPTSRC@
noinst_HEADERS = util.h
