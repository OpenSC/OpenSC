TOPDIR = ..\..

HEADERS			= pkcs11-opensc.h pkcs11.h sc-pkcs11.h

HEADERSDIR		= $(TOPDIR)\src\include\opensc

TARGET0                 = onepin-opensc-pkcs11.dll
TARGET                  = opensc-pkcs11.dll
TARGET2			= libpkcs11.lib
TARGET3			= pkcs11-spy.dll

OBJECTS			= pkcs11-global.obj pkcs11-session.obj pkcs11-object.obj misc.obj slot.obj \
			  mechanism.obj openssl.obj secretkey.obj framework-pkcs15.obj \
			  framework-pkcs15init.obj debug.obj \
			  versioninfo.res
OBJECTS2		= libpkcs11.obj versioninfo.res
OBJECTS3		= pkcs11-spy.obj pkcs11-display.obj libpkcs11.obj versioninfo.res

all: install-headers $(TARGET0) $(TARGET) $(TARGET2) $(TARGET3) 

!INCLUDE $(TOPDIR)\win32\Make.rules.mak

$(TARGET0): $(OBJECTS) hack-enabled.obj ..\libopensc\opensc.lib ..\scconf\scconf.lib ..\pkcs15init\pkcs15init.lib ..\common\common.lib
	echo LIBRARY $* > $*.def
	echo EXPORTS >> $*.def
	type opensc-pkcs11.exports >> $*.def
	link $(LINKFLAGS) /dll /def:$*.def /implib:$*.lib /out:$(TARGET0) $(OBJECTS) hack-enabled.obj ..\libopensc\opensc.lib ..\scconf\scconf.lib ..\pkcs15init\pkcs15init.lib ..\common\common.lib winscard.lib $(OPENSSL_LIB) $(LIBLTDL) gdi32.lib 
	if EXIST $(TARGET0).manifest mt -manifest $(TARGET0).manifest -outputresource:$(TARGET0);2

$(TARGET): $(OBJECTS) hack-disabled.obj ..\libopensc\opensc.lib ..\scconf\scconf.lib ..\pkcs15init\pkcs15init.lib ..\common\common.lib
	echo LIBRARY $* > $*.def
	echo EXPORTS >> $*.def
	type $*.exports >> $*.def
	link $(LINKFLAGS) /dll /def:$*.def /implib:$*.lib /out:$(TARGET) $(OBJECTS) hack-disabled.obj ..\libopensc\opensc.lib ..\scconf\scconf.lib ..\pkcs15init\pkcs15init.lib ..\common\common.lib winscard.lib $(OPENSSL_LIB) $(LIBLTDL) gdi32.lib
	if EXIST $(TARGET).manifest mt -manifest $(TARGET).manifest -outputresource:$(TARGET);2

$(TARGET2): $(OBJECTS2)
	lib /nologo /machine:ix86 /out:$(TARGET2) $(OBJECTS2) $(LIBLTDL_LIB)

$(TARGET3): $(OBJECTS3) ..\libopensc\opensc.lib
	echo LIBRARY $* > $*.def
	echo EXPORTS >> $*.def
	type $*.exports >> $*.def
	link $(LINKFLAGS) /dll /def:$*.def /implib:$*.lib /out:$(TARGET3) $(OBJECTS3) ..\libopensc\opensc.lib $(OPENSSL_LIB) $(LIBLTDL_LIB) gdi32.lib advapi32.lib
	if EXIST $(TARGET3).manifest mt -manifest $(TARGET3).manifest -outputresource:$(TARGET3);2
