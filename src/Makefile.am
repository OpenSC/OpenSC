MAINTAINERCLEANFILES = $(srcdir)/Makefile.in
EXTRA_DIST = Makefile.mak

# Order IS important
SUBDIRS = common scconf pkcs15init libisosm libopensc pkcs11 \
	tools tests minidriver

if ENABLE_SM
SUBDIRS += libsm smm
endif
