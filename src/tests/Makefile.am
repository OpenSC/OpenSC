# Process this file with automake to create Makefile.in

INCLUDES = -I$(top_srcdir)/src/libopensc
LDFLAGS = @LDFLAGS@ \
	$(top_srcdir)/src/libopensc/libopensc.la

noinst_PROGRAMS = base64 hst-test lottery p15dump \
		  pintest prngtest

COMMON_SRC = sc-test.c

base64_SOURCES = base64.c $(COMMON_SRC)
hst_test_SOURCES = hst-test.c $(COMMON_SRC)
lottery_SOURCES = lottery.c $(COMMON_SRC)
p15dump_SOURCES = p15dump.c $(COMMON_SRC)
pintest_SOURCES = pintest.c $(COMMON_SRC)
prngtest_SOURCES = prngtest.c $(COMMON_SRC)
