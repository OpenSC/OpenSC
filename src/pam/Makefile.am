# Process this file with automake to create Makefile.in

libdir = ${prefix}/lib/security

INCLUDES = -I../scam

LDFLAGS = @LDFLAGS@ @LIBDL@ @LIBPAM@ ../scam/libpamscam.la

SRC = pam_opensc.c pam_support.c pam_support.h

if HAVE_PAM
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
