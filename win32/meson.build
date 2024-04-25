configure_file(
    configuration: conf_aux,
    input: 'OpenSC.iss.in',
    output: 'OpenSC.iss'
)

if meson.get_compiler('cpp').get_id() == 'msvc'
    depwcautil = subproject('wcautil').get_variable('depwcautil')

    shared_library('customactions',
        modwindows.compile_resources(
            'customactions.rc',
            include_directories: core_inc
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

    progwix = find_program('wix', required: false)
    if progwix.found()
        wix_args = []
        if host_machine.cpu_family() == 'x86_64'
            wix_args += ['-arch', 'x64']
        elif host_machine.cpu_family() == 'aarch64'
            wix_args += ['-arch', 'arm64']
        elif host_machine.cpu_family() == 'x86'
            wix_args += ['-arch', 'x86']
        endif

        wix_args += get_option('components').contains('pkcs11')?     ['-d', 'ENABLE_PKCS11'] : []
        wix_args += get_option('components').contains('tools')?      ['-d', 'ENABLE_TOOLS']  : []
        wix_args += get_option('components').contains('minidriver')? ['-d', 'ENABLE_MINIDRIVER'] : []
        wix_args += get_option('components').contains('sm')?         ['-d', 'ENABLE_SM'] : []

        wix_args += get_option('static_components').contains('pkcs11')?     ['-d', 'STATIC_PKCS11'] : []
        wix_args += get_option('static_components').contains('tools')?      ['-d', 'STATIC_TOOLS'] : []
        wix_args += get_option('static_components').contains('minidriver')? ['-d', 'STATIC_MINIDRIVER'] : []
        wix_args += get_option('static_components').contains('sm')?         ['-d', 'STATIC_SM'] : []

        wix_args += conf.get('ENABLE_OPENPACE')? ['-d', 'ENABLE_OPENPACE'] : []
        wix_args += conf.get('ENABLE_OPENSSL')?  ['-d', 'ENABLE_OPENSSL'] : []
        wix_args += conf.get('ENABLE_NOTIFY')?   ['-d', 'ENABLE_NOTIFY'] : []

        run_target('msi',
            command: [progwix, 'build', wix_args,
                '-ext', 'WixToolset.Util.wixext',
                '-ext', 'WixToolset.UI.wixext',
                '-o', 'OpenSC-' + meson.project_version() + '.msi',
                meson.current_build_dir() / 'OpenSC.wxs'
            ]
        )
    endif
endif
