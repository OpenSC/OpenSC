# Process this file with automake to create Makefile.in

libdir = ${prefix}/lib/security

INCLUDES = @CFLAGS_PCSC@ @CFLAGS_OPENSC@ -I../scam -I../scconf -I../scrandom -I../scldap

if HAVE_LDAP
LDAP_LTLIBS = @LIBSCLDAP@
else
LDAP_LTLIBS = 
endif

LDFLAGS = @LDFLAGS@ @LIBDL@ @LIBSCRANDOM@ $(LDAP_LTLIBS) @LIBCRYPTO@ @LIBOPENSC@ @LIBPAM@

AUTHSRC = ../scam/scam.c ../scam/scam.h ../scam/p15_eid.c ../scam/p15_ldap.c
SRC = $(AUTHSRC) pam_opensc.c pam_support.c pam_support.h

if HAVE_PAM_AND_SSL
lib_LTLIBRARIES = pam_opensc.la
noinst_PROGRAMS = pam_opensc-test
else
lib_LTLIBRARIES = 
noinst_PROGRAMS = 
endif

pam_opensc_la_SOURCES = $(SRC)
pam_opensc_la_LDFLAGS = -module -avoid-version

pam_opensc_test_SOURCES = $(SRC) misc_conv.c
pam_opensc_test_CFLAGS = -DPAMTEST
