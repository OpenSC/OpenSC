# Process this file with automake to create Makefile.in

MAINTAINERCLEANFILES = Makefile.in

SUBDIRS = . regression

EXTRA_DIST = Makefile.mak

LDFLAGS = @LDFLAGS@ @LIBOPENSC@

noinst_PROGRAMS = base64 lottery p15dump pintest prngtest

SRC = sc-test.c
INC = sc-test.h

base64_SOURCES = base64.c $(SRC) $(INC)
base64_LDADD = @GETOPTSRC@
lottery_SOURCES = lottery.c $(SRC) $(INC)
lottery_LDADD = @GETOPTSRC@
p15dump_SOURCES = p15dump.c print.c $(SRC) $(INC)
p15dump_LDADD = @GETOPTSRC@
pintest_SOURCES = pintest.c print.c $(SRC) $(INC)
pintest_LDADD = @GETOPTSRC@
prngtest_SOURCES = prngtest.c $(SRC) $(INC)
prngtest_LDADD = @GETOPTSRC@
