libdir  = @libdir@/opensc

MAINTAINERCLEANFILES = Makefile.in

EXTRA_DIST = engine_opensc.c engine_opensc.h engine_pkcs11.c \
	     engine_pkcs11.h hw_opensc.c hw_pkcs11.c libpkcs11.h \
	     p11_attr.c p11_cert.c p11_err.c p11_key.c p11_load.c \
	     p11_misc.c p11_rsa.c p11_slot.c pkcs11-internal.h \
             test_engine.s

if HAVE_ENGINE
lib_LTLIBRARIES=engine_opensc.la engine_pkcs11.la
endif

engine_opensc_la_SOURCES = hw_opensc.c engine_opensc.c  
engine_opensc_la_CFLAGS =  -DOPENSSL_THREADS -D_REENTRANT -DDSO_DLFCN -DHAVE_DLFCN_H -DOPENSSL_NO_KRB5 -DL_ENDIAN -DTERMIO -DENGINE_DYNAMIC_SUPPORT -DSHA1_ASM -DMD5_ASM -DRMD160_ASM @CFLAGS_OPENSC@
engine_opensc_la_LIBADD = @LIBCRYPTOA@ @LIBOPENSC@ 
engine_opensc_la_LDFLAGS = -Wl,-Bsymbolic -module -avoid-version 

engine_pkcs11_la_SOURCES = hw_pkcs11.c engine_pkcs11.c \
			   p11_attr.c p11_cert.c p11_err.c p11_key.c p11_load.c p11_misc.c \
 	     		   p11_rsa.c p11_slot.c
engine_pkcs11_la_CFLAGS = -DOPENSSL_THREADS -D_REENTRANT -DDSO_DLFCN -DHAVE_DLFCN_H -DOPENSSL_NO_KRB5 -DL_ENDIAN -DTERMIO -DENGINE_DYNAMIC_SUPPORT -DSHA1_ASM -DMD5_ASM -DRMD160_ASM @CFLAGS_OPENSC@
engine_pkcs11_la_LIBADD = @LIBCRYPTOA@ ../pkcs11/.libs/libpkcs11.a 
engine_pkcs11_la_LDFLAGS = -Wl,-Bsymbolic -module -avoid-version 
