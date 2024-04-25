configure_file(
    configuration: conf_aux,
    input: 'OpenSC.iss.in',
    output: 'OpenSC.iss'
)

if meson.get_compiler('cpp').get_id() == 'msvc'
    depdutil = subproject('dutil').get_variable('depdutil')
    depwcautil = subproject('wcautil').get_variable('depwcautil')

    shared_library('customactions',
        modwindows.compile_resources(
            configure_file(
                configuration: conf_aux,
                input: 'versioninfo-customactions.rc.in',
                output: 'versioninfo-customactions.rc'
            )
        ),
        include_directories: core_inc,
        sources: files('customactions.cpp'),
        dependencies: [
            depdutil,
            depwcautil
        ]
    )

    configure_file(
        configuration: conf,
        input: 'OpenSC.wxs.in',
        output: 'OpenSC.wxs'
    )
endif
