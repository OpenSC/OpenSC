TOPDIR = ..\..

HEADERS			= pkcs11.h
HEADERSDIRFROM2		= rsaref

HEADERSDIR		= $(TOPDIR)\src\include\opensc
HEADERSDIR2		= $(TOPDIR)\src\include\opensc\rsaref

TARGET                  = opensc-pkcs11.dll
TARGET2			= libpkcs11.lib
TARGET3			= pkcs11-spy.dll

OBJECTS			= pkcs11-global.obj pkcs11-session.obj pkcs11-object.obj misc.obj slot.obj \
			  secretkey.obj framework-pkcs15.obj framework-pkcs15init.obj mechanism.obj \
			  openssl.obj debug.obj $(TOPDIR)\win32\version.res
OBJECTS2		= libpkcs11.obj
OBJECTS3		= pkcs11-spy.obj pkcs11-display.obj libpkcs11.obj

all: install-headers install-headers-dir $(TARGET) $(TARGET2) $(TARGET3)

!INCLUDE $(TOPDIR)\win32\Make.rules.mak

$(TARGET): $(OBJECTS) ..\libopensc\opensc.lib ..\scconf\scconf.lib ..\scrandom\scrandom.lib ..\pkcs15init\pkcs15init.lib ..\scdl\scdl.lib
	link $(LINKFLAGS) /dll /out:$(TARGET) $(OBJECTS) ..\libopensc\opensc.lib ..\scconf\scconf.lib ..\scrandom\scrandom.lib ..\pkcs15init\pkcs15init.lib winscard.lib ..\scdl\scdl.lib

$(TARGET2): $(OBJECTS2)  ..\scdl\scdl.lib
	lib /nologo /machine:ix86 /out:$(TARGET2) $(OBJECTS2) ..\scdl\scdl.lib

$(TARGET3): $(OBJECTS3) ..\libopensc\opensc.lib ..\scconf\scconf.lib ..\scdl\scdl.lib
	link $(LINKFLAGS) /dll /out:$(TARGET3) $(OBJECTS3) ..\libopensc\opensc.lib ..\scconf\scconf.lib ..\scdl\scdl.lib
