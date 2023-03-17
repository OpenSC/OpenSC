TOPDIR = ..\..

COMMON_OBJECTS = compat_getpass.obj compat_getopt.obj compat_strlcpy.obj compat_strlcat.obj simclist.obj compat_report_rangecheckfailure.obj compat___iob_func.obj compat_overflow.obj

all: common.lib libpkcs11.lib libscdl.lib

!INCLUDE $(TOPDIR)\win32\Make.rules.mak

common.lib: $(COMMON_OBJECTS)
	lib $(LIBFLAGS) /out:common.lib $(COMMON_OBJECTS)

libpkcs11.lib: libpkcs11.obj
	lib $(LIBFLAGS) /out:libpkcs11.lib libpkcs11.obj

libscdl.lib: libscdl.obj
	lib $(LIBFLAGS) /out:libscdl.lib libscdl.obj
