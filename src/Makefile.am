MAINTAINERCLEANFILES = $(srcdir)/Makefile.in
EXTRA_DIST = Makefile.mak

# Order IS important
SUBDIRS = common scconf pkcs15init libopensc pkcs11 \
	tools tests minidriver

if ENABLE_SM
SUBDIRS += libsm smm
endif
