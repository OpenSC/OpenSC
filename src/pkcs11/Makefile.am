# Process this file with automake to create Makefile.in

SUBDIRS = . pkcs11

libdir = ${prefix}/lib/pkcs11

INCLUDES = -I$(top_srcdir)/src/libopensc

LDFLAGS = @LDFLAGS@ @LIBDL@ \
	$(top_srcdir)/src/libopensc/libopensc.la

SRC = function_table.c generic.c session.c object.c \
	endecrypt.c digestsign.c verify.c misc.c slot.c
INC = sc-pkcs11.h

lib_LTLIBRARIES = libopensc-pkcs11.la

libopensc_pkcs11_la_SOURCES = $(SRC) $(INC)
libopensc_pkcs11_la_LDFLAGS = -module -version-info 1:0:0
