TOPDIR = ..\..

TARGET = opensc-minidriver.dll
OBJECTS = minidriver.obj versioninfo-minidriver.res
LIBS = $(TOPDIR)\src\libopensc\opensc_a.lib \
	   $(TOPDIR)\src\scconf\scconf.lib \
	   $(TOPDIR)\src\common\common.lib \
	   $(TOPDIR)\src\common\libscdl.lib \
	   $(TOPDIR)\src\ui\strings.lib \
	   $(TOPDIR)\src\ui\notify.lib \
	   $(TOPDIR)\src\sm\libsmiso.lib \
	   $(TOPDIR)\src\sm\libsmeac.lib \
	   $(TOPDIR)\src\pkcs15init\pkcs15init.lib

all: $(TARGET)

!INCLUDE $(TOPDIR)\win32\Make.rules.mak

$(TARGET): $(OBJECTS) $(LIBS)
	echo LIBRARY $* > $*.def
	echo EXPORTS >> $*.def
	type minidriver.exports >> $*.def
	link /dll $(LINKFLAGS) /def:$*.def /out:$(TARGET) $(OBJECTS) $(LIBS) $(ZLIB_LIB) $(OPENPACE_LIB) $(OPENSSL_LIB) ws2_32.lib gdi32.lib Comctl32.lib advapi32.lib Crypt32.lib User32.lib bcrypt.lib DelayImp.lib Rpcrt4.lib Shell32.lib Comctl32.lib Winmm.lib /DELAYLOAD:bcrypt.dll
	if EXIST $(TARGET).manifest mt -manifest $(TARGET).manifest -outputresource:$(TARGET);2
