# Process this file with automake to create Makefile.in

CC = ccmalloc gcc
INCLUDES = @CFLAGS_PCSC@ @CFLAGS_OPENSC@
LDFLAGS = @LDFLAGS@ @LIBOPENSC@

bin_PROGRAMS = opensc-tool opensc-explorer pkcs15-crypt pkcs15-tool

opensc_tool_SOURCES = opensc-tool.c util.c
opensc_tool_LDADD = @GETOPTSRC@
opensc_explorer_SOURCES = opensc-explorer.c util.c
opensc_explorer_LDADD = @GETOPTSRC@
pkcs15_tool_SOURCES = pkcs15-tool.c util.c
pkcs15_tool_LDADD = @GETOPTSRC@
pkcs15_crypt_SOURCES = pkcs15-crypt.c util.c
pkcs15_crypt_LDADD = @GETOPTSRC@
noinst_HEADERS = util.h
