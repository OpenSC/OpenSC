compat_lib = static_library('compat',
    'compat_dummy.c',
    'compat_strlcat.c',
    'compat_strlcpy.c',
    'compat_strnlen.c',
    'compat_getpass.c',
    'compat_getopt.c',
    'compat_report_rangecheckfailure.c',
    'compat___iob_func.c',
    'compat_overflow.c',
    'simclist.c',
    include_directories: core_inc,
    )

pkcs11_lib = static_library('pkcs11',
    'libpkcs11.c',
    include_directories: core_inc,
    )

scdl_lib = static_library('scdl',
    'libscdl.c',
    include_directories: core_inc,
    )