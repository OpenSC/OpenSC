libcompat = static_library('compat',
    get_variable('getopt_target', []),
    include_directories: core_inc,
    sources: files(
        'compat_dummy.c',
        'compat_getopt.c',
        'compat_getopt_main.c',
        'compat_getpass.c',
        'compat___iob_func.c',
        'compat_overflow.c',
        'compat_report_rangecheckfailure.c',
        'compat_strlcat.c',
        'compat_strlcpy.c',
        'compat_strnlen.c',
        'simclist.c'
    )
)

libscdl = static_library('scdl',
    include_directories: core_inc,
    sources: files('libscdl.c'),
    dependencies: depdl
)

libpkcs11_common = static_library('pkcs11',
    include_directories: core_inc,
    sources: files('libpkcs11.c'),
    link_with: libscdl
)

