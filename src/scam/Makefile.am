# Process this file with automake to create Makefile.in

MAINTAINERCLEANFILES = Makefile.in

INCLUDES = @CFLAGS_PCSC@ @CFLAGS_OPENSC@

lib_LTLIBRARIES = libscam.la

if HAVE_LDAP
LDAP_LTLIBS = @LIBSCLDAP@
endif
if HAVE_SSL
SSL_LTLIBS = @LIBCRYPTO@
endif
# Temporary
if HAVE_SCIDI
SCIDI_LTLIBS = @LIBSSP@
SCIDI_SRC = ../../../scam/sp.c
SCIDI_INC = @CFLAGS_SSP@
endif

LDFLAGS = @LIBOPENSC@ @LIBSCRANDOM@ $(LDAP_LTLIBS) $(SSL_LTLIBS) $(SCIDI_LTLIBS)
EXTRAINC = $(SCIDI_INC)

SRC = scam.c scam.h p15_eid.c p15_ldap.c $(SCIDI_SRC)

libscam_la_SOURCES = $(SRC)
libscam_la_LDFLAGS = -module -avoid-version
libscam_la_CFLAGS = $(EXTRAINC)
