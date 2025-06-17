libopensc_sources = files(
    'apdu.c',
    'asn1.c',
    'aux-data.c',
    'base64.c',
    'card-asepcos.c',
    'card-atrust-acos.c',
    'card-authentic.c',
    'card-belpic.c',
    'card.c',
    'card-cac1.c',
    'card-cac.c',
    'card-cac-common.c',
    'card-cardos.c',
    'card-cardos-common.c',
    'card-coolkey.c',
    'card-default.c',
    'card-dnie.c',
    'card-dtrust.c',
    'card-edo.c',
    'card-entersafe.c',
    'card-eoi.c',
    'card-epass2003.c',
    'card-esteid2018.c',
    'card-esteid2025.c',
    'card-flex.c',
    'card-gemsafeV1.c',
    'card-gids.c',
    'card-iasecc.c',
    'card-idprime.c',
    'card-isoApplet.c',
    'card-itacns.c',
    'card-jpki.c',
    'card-masktech.c',
    'card-mcrd.c',
    'card-muscle.c',
    'card-myeid.c',
    'card-npa.c',
    'card-nqApplet.c',
    'card-oberthur.c',
    'card-openpgp.c',
    'card-piv.c',
    'card-rtecp.c',
    'card-rutoken.c',
    'card-sc-hsm.c',
    'card-setcos.c',
    'card-skeid.c',
    'card-starcos.c',
    'card-tcos.c',
    'compression.c',
    'ctbcs.c',
    'ctx.c',
    'cwa14890.c',
    'cwa-dnie.c',
    'dir.c',
    'ef-atr.c',
    'ef-gdo.c',
    'errors.c',
    'gp.c',
    'iasecc-sdo.c',
    'iasecc-sm.c',
    'iso7816.c',
    'log.c',
    'muscle.c',
    'muscle-filesystem.c',
    'padding.c',
    'pkcs15-actalis.c',
    'pkcs15-algo.c',
    'pkcs15-atrust-acos.c',
    'pkcs15.c',
    'pkcs15-cac.c',
    'pkcs15-cache.c',
    'pkcs15-cardos.c',
    'pkcs15-cert.c',
    'pkcs15-coolkey.c',
    'pkcs15-data.c',
    'pkcs15-din-66291.c',
    'pkcs15-dnie.c',
    'pkcs15-dtrust.c',
    'pkcs15-emulator-filter.c',
    'pkcs15-eoi.c',
    'pkcs15-esinit.c',
    'pkcs15-esteid2018.c',
    'pkcs15-esteid2025.c',
    'pkcs15-gemsafeV1.c',
    'pkcs15-gids.c',
    'pkcs15-iasecc.c',
    'pkcs15-idprime.c',
    'pkcs15-itacns.c',
    'pkcs15-jpki.c',
    'pkcs15-nqApplet.c',
    'pkcs15-oberthur.c',
    'pkcs15-openpgp.c',
    'pkcs15-pin.c',
    'pkcs15-piv.c',
    'pkcs15-prkey.c',
    'pkcs15-pteid.c',
    'pkcs15-pubkey.c',
    'pkcs15-sc-hsm.c',
    'pkcs15-sec.c',
    'pkcs15-skeid.c',
    'pkcs15-skey.c',
    'pkcs15-starcert.c',
    'pkcs15-starcos-esign.c',
    'pkcs15-syn.c',
    'pkcs15-tccardos.c',
    'pkcs15-tcos.c',
    'reader-tr03119.c',
    'sc.c',
    'sec.c',
    'simpletlv.c',
    'sm.c'
)

libopensc_libraries = [
    libcompat,
    libscdl,
    libscconf,
    libstrings,
    libnotify,
    libpkcs15init,
    libsmeac
]

libopensc_dependencies = [
    depopenpace,
    depopenssl,
    depzlib
]

libopensc_targets = []
if host_machine.system() == 'windows' or host_machine.system() == 'cygwin'
    libopensc_targets += modwindows.compile_resources(
        'libopensc.rc',
        include_directories: core_inc,
        depend_files: 'opensc.dll.manifest'
    )
endif

libopensc_vs_defs = configure_file(
    configuration: {'EXPORTS': modfs.read('libopensc.exports')},
    input: 'libopensc.def.in',
    output: 'libopensc.def'
)

if conf.get('ENABLE_PCSC')
    libopensc_sources += files('reader-pcsc.c')
    libopensc_dependencies += deppcsc
endif

if conf.get('ENABLE_CRYPTOTOKENKIT')
    libopensc_sources += files('reader-cryptotokenkit.m')
    libopensc_dependencies += depcryptotokenkit
endif

if conf.get('ENABLE_OPENCT')
    libopensc_sources += files('reader-openct.c')
    libopensc_dependencies += depopenct
endif

if conf.get('ENABLE_CTAPI')
    libopensc_sources += files('reader-ctapi.c')
endif

libopensc_install = false
foreach component : get_option('components')
    if not (component in get_option('static_components'))
        libopensc_install = true
        break
    endif
endforeach

libopensc = shared_library('opensc',
    libopensc_targets,
    version: '11.0.2',
    include_directories: core_inc,
    sources: libopensc_sources,
    link_with: libopensc_libraries,
    dependencies: libopensc_dependencies,
    vs_module_defs: libopensc_vs_defs,
    install: libopensc_install
)

libopensc_static = static_library('opensc',
    objects: libopensc.extract_all_objects(recursive: true),
    link_with: libopensc_libraries,
    dependencies: libopensc_dependencies
)
