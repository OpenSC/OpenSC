# Process this file with automake to create Makefile.in

RM = rm -f

MAINTAINERCLEANFILES = Makefile.in \
	asn1.h \
	cardctl.h \
	emv.h \
	log.h \
	opensc.h \
	pkcs15.h \
	pkcs15-init.h \
	scconf.h \
	scldap.h \
	scrandom.h

all-local:
	@$(RM) *.h
	@$(LN_S) ../../libopensc/asn1.h asn1.h
	@$(LN_S) ../../libopensc/cardctl.h cardctl.h
	@$(LN_S) ../../libopensc/emv.h emv.h
	@$(LN_S) ../../libopensc/log.h log.h
	@$(LN_S) ../../libopensc/opensc.h opensc.h
	@$(LN_S) ../../libopensc/pkcs15.h pkcs15.h
	@$(LN_S) ../../pkcs15init/pkcs15-init.h pkcs15-init.h
	@$(LN_S) ../../scconf/scconf.h scconf.h
	@$(LN_S) ../../scldap/scldap.h scldap.h
	@$(LN_S) ../../scrandom/scrandom.h scrandom.h
