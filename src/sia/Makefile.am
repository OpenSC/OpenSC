# Process this file with automake to create Makefile.in

libdir = ${prefix}/lib/security

INCLUDES = -I../scam

LDFLAGS = @LDFLAGS@ @LIBDL@ ../scam/libsiascam.la

SRC = sia_opensc.c sia_support.c sia_support.h

if HAVE_SIA
lib_LTLIBRARIES = libsia_opensc.la
noinst_PROGRAMS = test-sia
else
lib_LTLIBRARIES = 
noinst_PROGRAMS = 
endif

libsia_opensc_la_SOURCES = $(SRC)
libsia_opensc_la_LDFLAGS = -module -avoid-version

test_sia_SOURCES = test-sia.c
