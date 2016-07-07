include $(top_srcdir)/win32/ltrc.inc

MAINTAINERCLEANFILES = $(srcdir)/Makefile.in
EXTRA_DIST = Makefile.mak

noinst_PROGRAMS = p11test

AM_CPPFLAGS = -I$(top_srcdir)/src
#LIBS = \
#	$(top_builddir)/src/libopensc/libopensc.la \
#	$(top_builddir)/src/common/libscdl.la \
#	$(top_builddir)/src/common/libcompat.la

p11test_SOURCES = p11test.c p11test_loader.c p11test_loader.h \
	p11test_case_common.h p11test_case_common.c \
	p11test_case_readonly.c p11test_case_readonly.h \
	p11test_case_mechs.c p11test_case_mechs.h \
	p11test_case_ec_sign.c p11test_case_ec_sign.h \
	p11test_case_wait.c p11test_case_wait.h \
	p11test_helpers.c p11test_helpers.h
#p11test_CFLAGS = -DNDEBUG
p11test_LDADD = -lssl -lcrypto -lcmocka

if WIN32
p11test_SOURCES += $(top_builddir)/win32/versioninfo.rc
endif
