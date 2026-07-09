configure_file(
    configuration: conf_aux,
    input: 'OpenSC.iss.in',
    output: 'OpenSC.iss'
)

if meson.get_compiler('cpp').get_id() == 'msvc'
    depwcautil = subproject('wcautil').get_variable('depwcautil')

    shared_library('customactions',
        modwindows.compile_resources(
            'versioninfo-customactions.rc',
            include_directories: core_inc
        ),
        include_directories: core_inc,
        sources: files('customactions.cpp'),
        dependencies: depwcautil,
        vs_module_defs: configure_file(
            configuration: {'EXPORTS': modfs.read('customactions.exports')},
            input: 'template.def.in',
            output: 'customactions.def'
        )
    )

    progwix = find_program('wix', required: false)
    if progwix.found()
        wix_args = ['-arch', target_arch]
        wix_args += ['-d', 'SOURCE_DIR=' + meson.project_source_root()]
        wix_args += ['-d', 'BUILD_DIR='  + meson.project_build_root()]

        wix_args += ['-d', 'PRODUCT_NAME='         + vmk['VS_FF_PRODUCT_NAME']]
        wix_args += ['-d', 'PRODUCT_BUGREPORT='    + vmk['PRODUCT_BUGREPORT']]
        wix_args += ['-d', 'PRODUCT_URL='          + vmk['PRODUCT_URL']]
        wix_args += ['-d', 'VS_FF_LEGAL_COMPANY_NAME=' + vmk['VS_FF_LEGAL_COMPANY_NAME']]
        wix_args += ['-d', 'VS_FF_LEGAL_COMPANY_URL='  + vmk['VS_FF_LEGAL_COMPANY_URL']]
        wix_args += ['-d', 'VS_FF_PRODUCT_UPDATES='    + vmk['VS_FF_PRODUCT_UPDATES']]

        wix_args += get_option('components').contains('pkcs11')?     ['-d', 'ENABLE_PKCS11'] : []
        wix_args += get_option('components').contains('tools')?      ['-d', 'ENABLE_TOOLS']  : []
        wix_args += get_option('components').contains('minidriver')? ['-d', 'ENABLE_MINIDRIVER'] : []
        wix_args += get_option('components').contains('sm')?         ['-d', 'ENABLE_SM'] : []

        wix_args += conf.get('ENABLE_OPENPACE')? ['-d', 'OpenPACE'] : []
        wix_args += conf.get('ENABLE_OPENSSL')?  ['-d', 'OpenSSL'] : []
        wix_args += conf.get('ENABLE_NOTIFY')?   ['-d', 'ENABLE_NOTIFY'] : []

        run_target('msi',
            command: [progwix, 'build', wix_args,
                '-ext', 'WixToolset.Util.wixext',
                '-ext', 'WixToolset.UI.wixext',
                '-o', vmk['PRODUCT_NAME'] + '-' + meson.project_version() + '_' + target_arch + '.msi',
                meson.project_source_root() / 'win32' / 'OpenSC.wxs'
            ]
        )
    endif
endif
