# Process this file with automake to create Makefile.in

libdir = @libdir@/security

MAINTAINERCLEANFILES = Makefile.in

INCLUDES = @CPPFLAGS@ -I${top_srcdir}/src/scam

LDFLAGS = @LDFLAGS@ @LIBDL@ @LIBPAM@ ${top_builddir}/src/scam/libscam.la

SRC = pam_opensc.c pam_support.c pam_support.h

if HAVE_PAM
lib_LTLIBRARIES = pam_opensc.la
noinst_PROGRAMS = test-pam
endif

pam_opensc_la_SOURCES = $(SRC)
pam_opensc_la_LDFLAGS = -module -avoid-version

test_pam_SOURCES = test-pam.c misc_conv.c
