# Process this file with automake to create Makefile.in

libdir = @libdir@/security

MAINTAINERCLEANFILES = Makefile.in

INCLUDES = -I${top_srcdir}/src/scam

AM_LDFLAGS = @LDFLAGS@ @LIBDL@ @LIBPAM@ ${top_builddir}/src/scam/libscam.la

SRC = pam_opensc.c pam_support.c pam_support.h

if HAVE_PAM
lib_LTLIBRARIES = pam_opensc.la
noinst_PROGRAMS = pam_opensc-test
endif

pam_opensc_la_SOURCES = $(SRC)
pam_opensc_la_LDFLAGS = -module -avoid-version

pam_opensc_test_SOURCES = pam_opensc.c pam_support.c pam_support.h misc_conv.c
pam_opensc_test_CFLAGS = -DPAMTEST
pam_opensc_test_LDADD = @LIBSCRANDOM@
