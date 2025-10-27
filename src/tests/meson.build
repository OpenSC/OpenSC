tests_targets = []
if host_machine.system() == 'windows' or host_machine.system() == 'cygwin'
    tests_targets += modwindows.compile_resources(
        'tests.rc',
        include_directories: core_inc,
        depend_files: 'tests.manifest'
    )
endif

libtest = static_library('common',
    include_directories: core_inc,
    sources: files('sc-test.c'),
    link_with: [
        libcompat,
        libopensc_static
    ]
)

foreach name, sources : {
    'base64':   files('base64.c'),
    'lottery':  files('lottery.c'),
    'p15dump':  files('p15dump.c', 'print.c'),
    'pintest':  files('pintest.c', 'print.c'),
    'prngtest': files('prngtest.c')
}

executable(name,
    tests_targets,
    include_directories: core_inc,
    sources: sources,
    link_with: libtest
)
endforeach

subdir('unittests')
subdir('p11test')
subdir('fuzzing')
