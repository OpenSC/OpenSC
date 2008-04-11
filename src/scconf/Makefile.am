include $(top_srcdir)/win32/ltrc.inc

MAINTAINERCLEANFILES = \
	$(srcdir)/Makefile.in $(srcdir)/versioninfo.rc
DISTCLEANFILES = lex-parse.c
CLEANFILES = versioninfo.rc
EXTRA_DIST = Makefile.mak

dist_noinst_DATA = README.scconf lex-parse.l
openscinclude_HEADERS = scconf.h
noinst_HEADERS = internal.h
noinst_PROGRAMS = test-conf
lib_LTLIBRARIES = libscconf.la

INCLUDES = -I$(top_srcdir)/src/common

libscconf_la_SOURCES = scconf.c parse.c write.c sclex.c \
	scconf.exports
if WIN32
libscconf_la_SOURCES += versioninfo.rc
else
dist_noinst_DATA += versioninfo.rc
endif
libscconf_la_LIBADD = $(top_builddir)/src/common/libcompat.la
libscconf_la_LDFLAGS = $(AM_LDFLAGS) \
	-version-info @OPENSC_LT_CURRENT@:@OPENSC_LT_REVISION@:@OPENSC_LT_AGE@ \
	-export-symbols "$(srcdir)/scconf.exports" \
	-no-undefined

test_conf_SOURCES = test-conf.c
test_conf_LDADD = libscconf.la

versioninfo.rc:
	sed 's/@@FILE_DESCRIPTION@@/OpenSC Core Library/g' \
		"$(top_builddir)/win32/versioninfo.rc.in" > versioninfo.rc
