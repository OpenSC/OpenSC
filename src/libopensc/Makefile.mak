TOPDIR = ..\..


TARGET                  = opensc.dll

HEADERS			= opensc.h pkcs15.h emv.h \
			  errors.h types.h \
			  cardctl.h asn1.h log.h

HEADERSDIR		= $(TOPDIR)\src\include\opensc

OBJECTS			= sc.obj ctx.obj module.obj asn1.obj log.obj base64.obj \
			  errors.obj sec.obj card.obj iso7816.obj dir.obj \
			  pkcs15.obj pkcs15-cert.obj pkcs15-pin.obj \
			  pkcs15-prkey.obj pkcs15-pubkey.obj pkcs15-sec.obj \
			  pkcs15-wrap.obj pkcs15-algo.obj \
			  pkcs15-cache.obj reader-pcsc.obj \
			  card-setcos.obj card-miocos.obj card-flex.obj card-gpk.obj \
			  card-etoken.obj card-tcos.obj card-emv.obj card-default.obj 

all: install-headers $(TARGET)

!INCLUDE $(TOPDIR)\win32\Make.rules.mak

$(TARGET): $(OBJECTS)
	perl $(TOPDIR)\win32\makedef.pl $*.def $* $(OBJECTS)
	link $(LINKFLAGS) /dll /def:$*.def /implib:$*.lib /out:$(TARGET) $(OBJECTS) ..\scconf\scconf.lib winscard.lib

