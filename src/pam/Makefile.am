# Process this file with automake to create Makefile.in

libdir = ${prefix}/lib/security

INCLUDES = @CFLAGS_PCSC@ @CFLAGS_OPENSC@
LDFLAGS = @LDFLAGS@ @LIBDL@ @LIBPAM@ @LIBCRYPTO@ @LIBOPENSC@

SRC = pam_pkcs15.c
INC = 

if HAVE_PAM_AND_SSL
lib_LTLIBRARIES = pam_pkcs15.la
noinst_PROGRAMS = pam_pkcs15-test
else
lib_LTLIBRARIES = 
noinst_PROGRAMS = 
endif

pam_pkcs15_la_SOURCES = $(SRC) $(INC)
pam_pkcs15_la_LDFLAGS = -module -avoid-version

pam_pkcs15_test_SOURCES = $(SRC) $(INC)
pam_pkcs15_test_CFLAGS = -DTEST
