# Process this file with automake to create Makefile.in

INCLUDES = -I$(top_srcdir)/src/libopensc
LDFLAGS = @LDFLAGS@ \
	$(top_srcdir)/src/libopensc/libopensc.la

bin_PROGRAMS = opensc-crypt opensc-tool

opensc_crypt_SOURCES = opensc-crypt.c util.c
opensc_tool_SOURCES = opensc-tool.c util.c
noinst_HEADERS = util.h
