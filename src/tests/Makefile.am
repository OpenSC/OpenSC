# Process this file with automake to create Makefile.in

INCLUDES = @CFLAGS_PCSC@ @CFLAGS_OPENSC@
LDFLAGS = @LDFLAGS@ @LIBOPENSC@

noinst_PROGRAMS = base64 lottery p15dump pintest prngtest

SRC = sc-test.c
INC = sc-test.h

base64_SOURCES = base64.c $(SRC) $(INC)
lottery_SOURCES = lottery.c $(SRC) $(INC)
p15dump_SOURCES = p15dump.c $(SRC) $(INC)
pintest_SOURCES = pintest.c $(SRC) $(INC)
prngtest_SOURCES = prngtest.c $(SRC) $(INC)
