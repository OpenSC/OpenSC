include $(top_srcdir)/win32/ltrc.inc

MAINTAINERCLEANFILES = $(srcdir)/Makefile.in
EXTRA_DIST = Makefile.mak tests.rc.in tests.manifest

SUBDIRS = regression p11test fuzzing unittests
noinst_PROGRAMS = base64 lottery p15dump pintest prngtest

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

if WIN32
base64_SOURCES += tests.rc
lottery_SOURCES += tests.rc
p15dump_SOURCES += tests.rc
pintest_SOURCES += tests.rc
prngtest_SOURCES += tests.rc
endif
