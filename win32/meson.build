configure_file(
    configuration: conf_aux,
    input: 'OpenSC.iss.in',
    output: 'OpenSC.iss'
)

if meson.get_compiler('cpp').get_id() == 'msvc'
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
        dependencies: depwcautil,
        vs_module_defs: configure_file(
            configuration: {'EXPORTS': modfs.read('customactions.exports')},
            input: 'customactions.def.in',
            output: 'customactions.def'
        )
    )

    configure_file(
        configuration: conf_aux,
        input: 'OpenSC-meson.wxs.in',
        output: 'OpenSC.wxs'
    )
endif
