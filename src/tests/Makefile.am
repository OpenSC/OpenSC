# Process this file with automake to create Makefile.in

INCLUDES = -I../libopensc
LDFLAGS = @LDFLAGS@ \
	../libopensc/libopensc.la

noinst_PROGRAMS = base64 hst-test lottery p15dump \
		  pintest prngtest

SRC = sc-test.c
INC = sc-test.h

base64_SOURCES = base64.c $(SRC) $(INC)
hst_test_SOURCES = hst-test.c $(SRC) $(INC)
lottery_SOURCES = lottery.c $(SRC) $(INC)
p15dump_SOURCES = p15dump.c $(SRC) $(INC)
pintest_SOURCES = pintest.c $(SRC) $(INC)
prngtest_SOURCES = prngtest.c $(SRC) $(INC)
