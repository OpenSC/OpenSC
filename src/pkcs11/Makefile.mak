TOPDIR = ..\..

TARGET1                 = opensc-pkcs11.dll
TARGET2                 = onepin-opensc-pkcs11.dll
TARGET3			= pkcs11-spy.dll

OBJECTS			= pkcs11-global.obj pkcs11-session.obj pkcs11-object.obj misc.obj slot.obj \
			  mechanism.obj openssl.obj framework-pkcs15.obj framework-pkcs15init.obj \
			  debug.obj pkcs11-display.obj versioninfo-pkcs11.res
OBJECTS3		= pkcs11-spy.obj pkcs11-display.obj versioninfo-pkcs11-spy.res

all: versioninfo-pkcs11.res $(TARGET1) $(TARGET2) $(TARGET3) versioninfo-pkcs11-spy.res

!INCLUDE $(TOPDIR)\win32\Make.rules.mak

$(TARGET1): $(OBJECTS) ..\libopensc\opensc_a.lib ..\pkcs15init\pkcs15init.lib
	echo LIBRARY $* > $*.def
	echo EXPORTS >> $*.def
	type opensc-pkcs11.exports >> $*.def
	link $(LINKFLAGS) /dll /def:$*.def /implib:$*.lib /out:$(TARGET1) $(OBJECTS) ..\libopensc\opensc_a.lib ..\pkcs15init\pkcs15init.lib $(OPENSSL_LIB) gdi32.lib
	if EXIST $(TARGET1).manifest mt -manifest $(TARGET1).manifest -outputresource:$(TARGET1);2

$(TARGET2): $(OBJECTS) ..\libopensc\opensc_a.lib ..\pkcs15init\pkcs15init.lib
	echo LIBRARY $* > $*.def
	echo EXPORTS >> $*.def
	type opensc-pkcs11.exports >> $*.def
	del pkcs11-global.obj
	cl $(CODE_OPTIMIZATION) $(COPTS) /DMODULE_APP_NAME=\"onepin-opensc-pkcs11\" /c pkcs11-global.c
	link $(LINKFLAGS) /dll /def:$*.def /implib:$*.lib /out:$(TARGET2) $(OBJECTS) ..\libopensc\opensc_a.lib ..\pkcs15init\pkcs15init.lib $(OPENSSL_LIB) gdi32.lib
	if EXIST $(TARGET2).manifest mt -manifest $(TARGET2).manifest -outputresource:$(TARGET2);2

$(TARGET3): $(OBJECTS3) ..\libopensc\opensc.lib
	echo LIBRARY $* > $*.def
	echo EXPORTS >> $*.def
	type $*.exports >> $*.def
	link $(LINKFLAGS) /dll /def:$*.def /implib:$*.lib /out:$(TARGET3) $(OBJECTS3) ..\libopensc\opensc.lib ..\common\libpkcs11.lib ..\common\libscdl.lib $(OPENSSL_LIB) gdi32.lib advapi32.lib
	if EXIST $(TARGET3).manifest mt -manifest $(TARGET3).manifest -outputresource:$(TARGET3);2
