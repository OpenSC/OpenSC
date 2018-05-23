include $(top_srcdir)/win32/ltrc.inc

MAINTAINERCLEANFILES = $(srcdir)/Makefile.in 
EXTRA_DIST = Makefile.mak

noinst_LTLIBRARIES = libstrings.la libnotify.la
noinst_HEADERS = strings.h notify.h wchar_from_char_str.h char_str_from_wchar.h invisible_window.h

AM_CPPFLAGS = -I$(top_srcdir)/src
AM_CFLAGS = $(OPTIONAL_OPENSSL_CFLAGS) $(OPTIONAL_NOTIFY_CFLAGS)
AM_OBJCFLAGS = $(AM_CFLAGS)

libstrings_la_SOURCES = strings.c

libnotify_la_SOURCES = notify.c
libnotify_la_LIBADD = $(OPTIONAL_NOTIFY_LIBS)
