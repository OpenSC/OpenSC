TOPDIR = ..\..

TARGET                  = engine_pkcs11.dll

OBJECTS			= engine_pkcs11.obj hw_pkcs11.obj

all: $(TARGET)

!INCLUDE $(TOPDIR)\win32\Make.rules.mak

$(TARGET): $(OBJECTS) ..\libp11\libp11.lib ..\scconf\scconf.lib
	link $(LINKFLAGS) /dll /def:$*.def /implib:$*.lib /out:$(TARGET) $(OBJECTS) ..\libp11\libp11.lib ..\scconf\scconf.lib winscard.lib $(OPENSSL_LIB) gdi32.lib
