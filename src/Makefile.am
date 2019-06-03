MAINTAINERCLEANFILES = $(srcdir)/Makefile.in
EXTRA_DIST = Makefile.mak

# Order IS important
SUBDIRS = common scconf ui pkcs15init sm \
		  libopensc pkcs11 tools minidriver tests

if ENABLE_SM
SUBDIRS += smm
endif
