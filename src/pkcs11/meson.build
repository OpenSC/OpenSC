pkcs11_sources = files('pkcs11-global.c',
    'pkcs11-session.c',
    'pkcs11-object.c',
    'misc.c',
    'slot.c',
    'mechanism.c',
    'openssl.c',
    'framework-pkcs15.c',
    'framework-pkcs15init.c',
    'debug.c',
    'pkcs11-display.c',
)

pkcs11_mod = shared_module('opensc-pkcs11',
    pkcs11_sources,
    include_directories: core_inc,
    dependencies: [openssl_dep, openpace_dep],
)

pkcs11_mod = shared_module('onepin-opensc-pkcs11',
    pkcs11_sources,
    c_args: ['-DMODULE_APP_NAME="onepin-opensc-pkcs11"'],
    include_directories: core_inc,
    dependencies: [openssl_dep, openpace_dep],
)
