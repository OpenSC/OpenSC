# Process this file with automake to create Makefile.in

libdir = ${prefix}/lib/security

INCLUDES = @CFLAGS_PCSC@ @CFLAGS_SSP@ @CFLAGS_OPENSC@ -I../scam -I../scconf -I../scrandom -I../scldap

if HAVE_LDAP
LDAP_LTLIBS = @LIBSCLDAP@
else
LDAP_LTLIBS = 
endif

LDFLAGS = @LDFLAGS@ @LIBDL@ @LIBSCRANDOM@ $(LDAP_LTLIBS) @LIBSSP@ @LIBOPENSC@

AUTHSRC = ../scam/scam.c ../scam/scam.h ../scam/sp.c ../scam/p15_eid.c ../scam/p15_ldap.c
SRC = $(AUTHSRC) sia_opensc.c sia_support.c sia_support.h

if HAVE_SIA
lib_LTLIBRARIES = libsia_opensc.la
noinst_PROGRAMS = test-sia
else
lib_LTLIBRARIES = 
noinst_PROGRAMS = 
endif

libsia_opensc_la_SOURCES = $(SRC) $(INC)
libsia_opensc_la_LDFLAGS = -module -avoid-version

test_sia_SOURCES = test-sia.c
