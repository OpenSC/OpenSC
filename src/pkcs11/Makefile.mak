TOPDIR = ..\..

TARGET1                 = opensc-pkcs11.dll
TARGET3			= pkcs11-spy.dll

OBJECTS			= pkcs11-global.obj pkcs11-session.obj pkcs11-object.obj misc.obj slot.obj \
			  mechanism.obj openssl.obj framework-pkcs15.obj \
			  framework-pkcs15init.obj debug.obj pkcs11-display.obj \
				$(TOPDIR)\win32\versioninfo.res
OBJECTS3		= pkcs11-spy.obj pkcs11-display.obj \
				$(TOPDIR)\win32\versioninfo.res

all: $(TOPDIR)\win32\versioninfo.res $(TARGET0) $(TARGET1) $(TARGET3)

!INCLUDE $(TOPDIR)\win32\Make.rules.mak

$(TARGET1): $(OBJECTS) ..\libopensc\opensc_a.lib ..\pkcs15init\pkcs15init.lib
	echo LIBRARY $* > $*.def
	echo EXPORTS >> $*.def
	type opensc-pkcs11.exports >> $*.def
	link $(LINKFLAGS) /dll /def:$*.def /implib:$*.lib /out:$(TARGET1) $(OBJECTS) ..\libopensc\opensc_a.lib ..\pkcs15init\pkcs15init.lib $(OPENSSL_LIB) gdi32.lib
	if EXIST $(TARGET1).manifest mt -manifest $(TARGET1).manifest -outputresource:$(TARGET1);2

$(TARGET3): $(OBJECTS3) ..\libopensc\opensc.lib
	echo LIBRARY $* > $*.def
	echo EXPORTS >> $*.def
	type $*.exports >> $*.def
	link $(LINKFLAGS) /dll /def:$*.def /implib:$*.lib /out:$(TARGET3) $(OBJECTS3) ..\libopensc\opensc.lib ..\common\libpkcs11.lib ..\common\libscdl.lib $(OPENSSL_LIB) gdi32.lib advapi32.lib
	if EXIST $(TARGET3).manifest mt -manifest $(TARGET3).manifest -outputresource:$(TARGET3);2
