# Process this file with automake to create Makefile.in

libdir = ${prefix}/lib/security

INCLUDES = -I$(top_srcdir)/src/libopensc
LDFLAGS = @LDFLAGS@ @LIBDL@ @LIBPAM@ @LIBCRYPTO@ \
	$(top_srcdir)/src/libopensc/libopensc.la

SRC = pam_pkcs15.c
INC = 

if HAVE_PAM_AND_SSL
lib_LTLIBRARIES = libpam_pkcs15.la
noinst_PROGRAMS = pam_pkcs15-test
else
lib_LTLIBRARIES = 
noinst_PROGRAMS = 
endif

libpam_pkcs15_la_SOURCES = $(SRC) $(INC)
libpam_pkcs15_la_LDFLAGS = -module -avoid-version

pam_pkcs15_test_SOURCES = $(SRC) $(INC)
pam_pkcs15_test_CFLAGS = -DTEST

if HAVE_PAM_AND_SSL

install-exec-local: install-libLTLIBRARIES
	@$(NORMAL_INSTALL)
	-rm -f $(DESTDIR)$(libdir)/pam_pkcs15.so
	-cd $(DESTDIR)$(libdir) && ln -s libpam_pkcs15.so pam_pkcs15.so

endif
