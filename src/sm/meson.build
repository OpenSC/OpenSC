sm_lib = static_library('sm',
    'sm-common.c',
    include_directories: core_inc,
    dependencies: [openssl_dep])

smiso_lib = static_library('smiso',
    'sm-iso.c',
    include_directories: core_inc)

smeac_lib = static_library('smeac',
    'sm-eac.c',
    include_directories: core_inc,
    link_with: [smiso_lib],
    dependencies: [openssl_dep, openpace_dep])
