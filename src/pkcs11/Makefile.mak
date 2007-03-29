TOPDIR = ..\..

HEADERS			= pkcs11.h

HEADERSDIR		= $(TOPDIR)\src\include\opensc

TARGET0                 = onepin-opensc-pkcs11.dll
TARGET                  = opensc-pkcs11.dll
TARGET2			= libpkcs11.lib
TARGET3			= pkcs11-spy.dll

OBJECTS			= pkcs11-global.obj pkcs11-session.obj pkcs11-object.obj misc.obj slot.obj \
			  secretkey.obj framework-pkcs15.obj framework-pkcs15init.obj mechanism.obj \
			  openssl.obj debug.obj $(TOPDIR)\win32\version.res
OBJECTS2		= libpkcs11.obj
OBJECTS3		= pkcs11-spy.obj pkcs11-display.obj libpkcs11.obj

all: install-headers $(TARGET0) $(TARGET) $(TARGET2) $(TARGET3) 

!INCLUDE $(TOPDIR)\win32\Make.rules.mak

$(TARGET0): $(OBJECTS) hack-enabled.obj ..\libopensc\opensc.lib ..\scconf\scconf.lib ..\pkcs15init\pkcs15init.lib ..\common\common.lib
	link $(LINKFLAGS) /dll /out:$(TARGET) $(OBJECTS) hack-enabled.obj ..\libopensc\opensc.lib ..\scconf\scconf.lib ..\pkcs15init\pkcs15init.lib ..\common\common.lib winscard.lib $(OPENSSL_LIB) $(LIBLTDL) gdi32.lib
	if EXIST $(TARGET).manifest mt -manifest $(TARGET).manifest -outputresource:$(TARGET);2

$(TARGET): $(OBJECTS) hack-disabled.obj ..\libopensc\opensc.lib ..\scconf\scconf.lib ..\pkcs15init\pkcs15init.lib ..\common\common.lib
	link $(LINKFLAGS) /dll /out:$(TARGET) $(OBJECTS) hack-disabled.obj ..\libopensc\opensc.lib ..\scconf\scconf.lib ..\pkcs15init\pkcs15init.lib ..\common\common.lib winscard.lib $(OPENSSL_LIB) $(LIBLTDL) gdi32.lib
	if EXIST $(TARGET).manifest mt -manifest $(TARGET).manifest -outputresource:$(TARGET);2

$(TARGET2): $(OBJECTS2)
	lib /nologo /machine:ix86 /out:$(TARGET2) $(OBJECTS2) $(LIBLTDL_LIB)

$(TARGET3): $(OBJECTS3) ..\libopensc\opensc.lib
	link $(LINKFLAGS) /dll /out:$(TARGET3) $(OBJECTS3) ..\libopensc\opensc.lib $(OPENSSL_LIB) $(LIBLTDL_LIB) gdi32.lib advapi32.lib
	if EXIST $(TARGET3).manifest mt -manifest $(TARGET3).manifest -outputresource:$(TARGET3);2
