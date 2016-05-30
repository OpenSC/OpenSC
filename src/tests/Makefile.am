include $(top_srcdir)/win32/ltrc.inc

MAINTAINERCLEANFILES = $(srcdir)/Makefile.in
EXTRA_DIST = Makefile.mak

SUBDIRS = regression
noinst_PROGRAMS = base64 lottery p15dump pintest prngtest p11test

AM_CPPFLAGS = -I$(top_srcdir)/src
AM_CFLAGS = $(OPTIONAL_OPENSSL_CFLAGS)
LIBS = \
	$(top_builddir)/src/libopensc/libopensc.la \
	$(top_builddir)/src/common/libscdl.la \
	$(top_builddir)/src/common/libcompat.la

COMMON_SRC = sc-test.c
COMMON_INC = sc-test.h

base64_SOURCES = base64.c $(COMMON_SRC) $(COMMON_INC)
lottery_SOURCES = lottery.c $(COMMON_SRC) $(COMMON_INC)
p15dump_SOURCES = p15dump.c print.c $(COMMON_SRC) $(COMMON_INC)
pintest_SOURCES = pintest.c print.c $(COMMON_SRC) $(COMMON_INC)
prngtest_SOURCES = prngtest.c $(COMMON_SRC) $(COMMON_INC)
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
base64_SOURCES += $(top_builddir)/win32/versioninfo.rc
lottery_SOURCES += $(top_builddir)/win32/versioninfo.rc
p15dump_SOURCES += $(top_builddir)/win32/versioninfo.rc
pintest_SOURCES += $(top_builddir)/win32/versioninfo.rc
prngtest_SOURCES += $(top_builddir)/win32/versioninfo.rc
p11test_SOURCES += $(top_builddir)/win32/versioninfo.rc
endif
