TOPDIR = ..\..

TARGET                  = engine_pkcs11.dll

OBJECTS			= engine_pkcs11.obj hw_pkcs11.obj p11_attr.obj p11_cert.obj \
                          p11_err.obj p11_key.obj p11_load.obj p11_misc.obj p11_rsa.obj \
                          p11_slot.obj

all: $(TARGET)

!INCLUDE $(TOPDIR)\win32\Make.rules.mak

$(TARGET): $(OBJECTS)
	link $(LINKFLAGS) /dll /def:$*.def /implib:$*.lib /out:$(TARGET) $(OBJECTS) ..\pkcs11\libpkcs11.obj ..\scconf\scconf.lib winscard.lib libeay32.lib gdi32.lib
