# Process this file with automake to create Makefile.in

MAINTAINERCLEANFILES = Makefile.in

INCLUDES = @CFLAGS_PCSC@ @CFLAGS_OPENSC@

if HAVE_PAM
PAM = libpamscam.la
endif
if HAVE_SIA
SIA = libsiascam.la
endif

lib_LTLIBRARIES = $(PAM) $(SIA)

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

libpamscam_la_SOURCES = $(SRC)
libpamscam_la_LDFLAGS = -module -avoid-version
libpamscam_la_CFLAGS = -I../pam -DPAM_SCAM $(EXTRAINC)

libsiascam_la_SOURCES = $(SRC)
libsiascam_la_LDFLAGS = -module -avoid-version
libsiascam_la_CFLAGS = -I../sia -DSIA_SCAM $(EXTRAINC)
