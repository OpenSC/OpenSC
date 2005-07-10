TOPDIR = ..\..

TARGET                  = libp11.dll

OBJECTS                 = p11_attr.obj p11_cert.obj p11_err.obj \
	p11_key.obj p11_load.obj p11_misc.obj p11_rsa.obj p11_slot.obj

all: $(TARGET)

!INCLUDE $(TOPDIR)\win32\Make.rules.mak

$(TARGET): $(OBJECTS) ..\scdl\scdl.lib 
	perl $(TOPDIR)\win32\makedef.pl $*.def $* $(OBJECTS)
	link $(LINKFLAGS) /dll /def:$*.def /implib:$*.lib /out:$(TARGET) $(OBJECTS) ..\scdl\scdl.lib $(OPENSSL_LIB)
