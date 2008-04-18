MAINTAINERCLEANFILES = $(srcdir)/Makefile.in
EXTRA_DIST = svnignore

all-local:
	@-rm -f *.h
	@$(LN_S) $(top_srcdir)/src/libopensc/asn1.h asn1.h
	@$(LN_S) $(top_srcdir)/src/libopensc/cardctl.h cardctl.h
	@$(LN_S) $(top_srcdir)/src/libopensc/cards.h cards.h
	@$(LN_S) $(top_srcdir)/src/libopensc/emv.h emv.h
	@$(LN_S) $(top_srcdir)/src/libopensc/errors.h errors.h
	@$(LN_S) $(top_srcdir)/src/libopensc/log.h log.h
	@$(LN_S) $(top_srcdir)/src/libopensc/opensc.h opensc.h
	@$(LN_S) $(top_srcdir)/src/libopensc/pkcs15.h pkcs15.h
	@$(LN_S) $(top_srcdir)/src/libopensc/types.h types.h
	@$(LN_S) $(top_srcdir)/src/libopensc/ui.h ui.h
	@$(LN_S) $(top_srcdir)/src/pkcs11/pkcs11.h pkcs11.h
	@$(LN_S) $(top_srcdir)/src/pkcs11/pkcs11-opensc.h pkcs11-opensc.h
	@$(LN_S) $(top_srcdir)/src/pkcs15init/keycache.h keycache.h
	@$(LN_S) $(top_srcdir)/src/pkcs15init/pkcs15-init.h pkcs15-init.h
	@$(LN_S) $(top_srcdir)/src/scconf/scconf.h scconf.h

distclean-local:
	-rm -f *.h
