# Process this file with automake to create Makefile.in

RM = rm -f

SUBDIRS = . rsaref

MAINTAINERCLEANFILES = Makefile.in
DISTCLEANFILES = \
	asn1.h \
	cardctl.h \
	emv.h \
	errors.h \
	log.h \
	opensc.h \
	pkcs15.h \
	types.h \
	ui.h \
	pkcs11.h \
	keycache.h \
	pkcs15-init.h \
	scconf.h \
	scdl.h \
	scldap.h \
	scrandom.h

all-local:
	@$(RM) *.h
	@$(LN_S) ${top_srcdir}/src/libopensc/asn1.h asn1.h
	@$(LN_S) ${top_srcdir}/src/libopensc/cardctl.h cardctl.h
	@$(LN_S) ${top_srcdir}/src/libopensc/emv.h emv.h
	@$(LN_S) ${top_srcdir}/src/libopensc/errors.h errors.h
	@$(LN_S) ${top_srcdir}/src/libopensc/log.h log.h
	@$(LN_S) ${top_srcdir}/src/libopensc/opensc.h opensc.h
	@$(LN_S) ${top_srcdir}/src/libopensc/pkcs15.h pkcs15.h
	@$(LN_S) ${top_srcdir}/src/libopensc/types.h types.h
	@$(LN_S) ${top_srcdir}/src/libopensc/ui.h ui.h
	@$(LN_S) ${top_srcdir}/src/pkcs11/pkcs11.h pkcs11.h
	@$(LN_S) ${top_srcdir}/src/pkcs15init/keycache.h keycache.h
	@$(LN_S) ${top_srcdir}/src/pkcs15init/pkcs15-init.h pkcs15-init.h
	@$(LN_S) ${top_srcdir}/src/scconf/scconf.h scconf.h
	@$(LN_S) ${top_srcdir}/src/scdl/scdl.h scdl.h
	@$(LN_S) ${top_srcdir}/src/scldap/scldap.h scldap.h
	@$(LN_S) ${top_srcdir}/src/scrandom/scrandom.h scrandom.h
