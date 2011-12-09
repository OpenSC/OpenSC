TOPDIR = ..\..

COMMON_OBJECTS = compat_getpass.obj compat_getopt.obj compat_strlcpy.obj compat_strlcat.obj simclist.obj

all: common.lib libpkcs11.lib libscdl.lib

common.lib: $(COMMON_OBJECTS)
	lib $(LIBFLAGS) /out:common.lib $(COMMON_OBJECTS)

libpkcs11.lib: libpkcs11.obj libscdl.obj
	lib $(LIBFLAGS) /out:libpkcs11.lib libpkcs11.obj

libscdl.lib: libscdl.obj
	lib $(LIBFLAGS) /out:libscdl.lib libscdl.obj

!INCLUDE $(TOPDIR)\win32\Make.rules.mak

