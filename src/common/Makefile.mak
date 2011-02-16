TOPDIR = ..\..

COMMON_OBJECTS = compat_getpass.obj compat_getopt.obj compat_strlcpy.obj compat_strlcat.obj simclist.obj

all: common.lib libpkcs11.lib libscdl.lib

common.lib: $(COMMON_OBJECTS)
	lib /nologo /machine:ix86 /out:common.lib $(COMMON_OBJECTS)

libpkcs11.lib: libpkcs11.obj libscdl.obj
	lib /nologo /machine:ix86 /out:libpkcs11.lib libpkcs11.obj libscdl.obj

libscdl.lib: libscdl.obj
	lib /nologo /machine:ix86 /out:libscdl.lib libscdl.obj

!INCLUDE $(TOPDIR)\win32\Make.rules.mak

