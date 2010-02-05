include $(top_srcdir)/win32/ltrc.inc

MAINTAINERCLEANFILES = $(srcdir)/Makefile.in 

EXTRA_DIST = Makefile.mak

lib_LTLIBRARIES =  

INCLUDES = -I$(top_builddir)/src/include \
	-I$(top_srcdir)/src/common \
	-I$(top_srcdir)/src/libopensc

opensc_cardmod_la_SOURCES = cardmod.c cardmod.exports
opensc_cardmod_la_LIBADD =  $(LTLIB_LIBS) \
	$(top_builddir)/src/libopensc/libopensc.la
opensc_cardmod_la_LDFLAGS = $(AM_LDFLAGS) \
	-export-symbols "$(srcdir)/cardmod.exports" \
	-module -avoid-version -no-undefined

if CARDMOD
sbin_SCRIPTS = cardmod.inf cardmod-westcos.reg
lib_LTLIBRARIES += opensc-cardmod.la
opensc_cardmod_la_SOURCES += $(top_builddir)/win32/versioninfo.rc
opensc_cardmod_la_LIBADD += -lcrypt32
install-exec-hook:
	mv "$(DESTDIR)$(libdir)/opensc-cardmod.dll" "$(DESTDIR)$(bindir)/" 
else
dist_noinst_SCRIPTS = cardmod.inf cardmod-westcos.reg
endif

