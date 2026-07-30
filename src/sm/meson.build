libsmeac = static_library('smeac',
    include_directories: core_inc,
    sources: files(
        'sm-eac.c',
        'sm-iso.c'
    ),
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
