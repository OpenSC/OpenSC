# Process this file with automake to create Makefile.in

RM = rm -f

MAINTAINERCLEANFILES = Makefile.in
DISTCLEANFILES = \
	pkcs11.h \
	pkcs11f.h \
	pkcs11t.h \
	unix.h \
	win32.h

all-local:
	@$(RM) *.h
	@$(LN_S) ${top_srcdir}/src/pkcs11/rsaref/pkcs11.h pkcs11.h
	@$(LN_S) ${top_srcdir}/src/pkcs11/rsaref/pkcs11f.h pkcs11f.h
	@$(LN_S) ${top_srcdir}/src/pkcs11/rsaref/pkcs11t.h pkcs11t.h
	@$(LN_S) ${top_srcdir}/src/pkcs11/rsaref/unix.h unix.h
	@$(LN_S) ${top_srcdir}/src/pkcs11/rsaref/win32.h win32.h

