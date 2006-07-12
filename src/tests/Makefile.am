# Process this file with automake to create Makefile.in

MAINTAINERCLEANFILES = Makefile.in

SUBDIRS = . regression

EXTRA_DIST = Makefile.mak

AM_LDFLAGS = @LIBOPENSC@ $(LTLIBLTDL)
AM_CFLAGS = -I$(top_srcdir)/src/common

noinst_PROGRAMS = base64 lottery p15dump pintest prngtest

SRC = sc-test.c $(top_srcdir)/src/common/my_getopt.c
INC = sc-test.h

base64_SOURCES = base64.c $(SRC) $(INC)
lottery_SOURCES = lottery.c $(SRC) $(INC)
p15dump_SOURCES = p15dump.c print.c $(SRC) $(INC)
pintest_SOURCES = pintest.c print.c $(SRC) $(INC)
prngtest_SOURCES = prngtest.c $(SRC) $(INC)
