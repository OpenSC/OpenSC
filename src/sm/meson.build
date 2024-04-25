libsmiso = static_library('smiso',
    include_directories: core_inc,
    sources: files('sm-iso.c')
)

libsmeac = static_library('smeac',
    include_directories: core_inc,
    sources: files('sm-eac.c'),
    link_with: libsmiso,
    dependencies: [
        depopenpace,
        depopenssl
    ]
)

if conf.get('ENABLE_OPENSSL')
    libsm = static_library('sm',
        include_directories: core_inc,
        sources: files('sm-common.c'),
        dependencies: depopenssl
    )
endif
