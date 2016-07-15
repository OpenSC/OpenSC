MAINTAINERCLEANFILES = $(srcdir)/Makefile.in
EXTRA_DIST = Makefile.mak

# Order IS important
SUBDIRS = common scconf pkcs15init libsm libsceac \
		  libopensc libcardnpa pkcs11 tools tests minidriver

if ENABLE_SM
SUBDIRS += smm
endif
