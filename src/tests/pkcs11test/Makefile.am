MAINTAINERCLEANFILES = $(srcdir)/Makefile.in
EXTRA_DIST = Makefile.mak

if ENABLE_LIBXML2

AM_CPPFLAGS = -I$(top_srcdir)/src

noinst_PROGRAMS = pkcs11test

noinst_HEADERS = pkcs11test_process.h pkcs11test_common.h pkcs11test_types.h \
    pkcs11test_func.h pkcs11test_params_check.h pkcs11test_str.h pkcs11test_prop_parse.h \
    pkcs11test_params_parse.h pkcs11test_value_check.h pkcs11test_prop_check.h \
    pkcs11test_value_getter.h

pkcs11test_SOURCES = pkcs11test.c pkcs11test_process.c pkcs11test_common.c \
    pkcs11test_func.c pkcs11test_params_check.c pkcs11test_str.c pkcs11test_prop_parse.c \
    pkcs11test_params_parse.c pkcs11test_value_check.c pkcs11test_prop_check.c \
    pkcs11test_value_getter.c

pkcs11test_CFLAGS = $(LIBXML2_CFLAGS)
pkcs11test_LDADD = $(LIBXML2_LIBS) $(LDL_LIBS)

if WIN32
pkcs11test_SOURCES += $(top_builddir)/win32/versioninfo.rc
endif

endif
