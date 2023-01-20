TOPDIR = ..\..

TARGET1			= opensc-pkcs11.dll
TARGET3			= pkcs11-spy.dll

OBJECTS			= pkcs11-global.obj pkcs11-session.obj pkcs11-object.obj misc.obj slot.obj \
				  mechanism.obj openssl.obj framework-pkcs15.obj framework-pkcs15init.obj \
				  debug.obj pkcs11-display.obj versioninfo-pkcs11.res
OBJECTS3		= pkcs11-spy.obj pkcs11-display.obj versioninfo-pkcs11-spy.res

LIBS = $(TOPDIR)\src\libopensc\opensc_a.lib \
	   $(TOPDIR)\src\pkcs15init\pkcs15init.lib \
	   $(TOPDIR)\src\scconf\scconf.lib \
	   $(TOPDIR)\src\common\common.lib \
	   $(TOPDIR)\src\common\libscdl.lib \
	   $(TOPDIR)\src\ui\strings.lib \
	   $(TOPDIR)\src\ui\notify.lib \
	   $(TOPDIR)\src\sm\libsmiso.lib \
	   $(TOPDIR)\src\sm\libsmeac.lib \
	   $(TOPDIR)\src\pkcs15init\pkcs15init.lib
LIBS3 = $(TOPDIR)\src\common\libpkcs11.lib $(TOPDIR)\src\common\libscdl.lib $(TOPDIR)\src\common\common.lib

all: $(TARGET1) $(TARGET3)

!INCLUDE $(TOPDIR)\win32\Make.rules.mak

$(TARGET1): $(OBJECTS) $(LIBS)
	link $(LINKFLAGS) /dll /implib:$*.lib /out:$(TARGET1) $(OBJECTS) $(LIBS) $(OPENPACE_LIB) $(OPENSSL_LIB) $(ZLIB_LIB) gdi32.lib Comctl32.lib Shell32.lib user32.lib advapi32.lib ws2_32.lib Shell32.lib Comctl32.lib shlwapi.lib
	if EXIST $(TARGET1).manifest mt -manifest $(TARGET1).manifest -outputresource:$(TARGET1);2

$(TARGET3): $(OBJECTS3) $(LIBS3)
	link $(LINKFLAGS) /dll /implib:$*.lib /out:$(TARGET3) $(OBJECTS3) $(LIBS3) $(OPENSSL_LIB) gdi32.lib advapi32.lib shlwapi.lib
	if EXIST $(TARGET3).manifest mt -manifest $(TARGET3).manifest -outputresource:$(TARGET3);2
