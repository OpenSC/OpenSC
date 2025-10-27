project('wcautil', 'cpp')

if meson.get_compiler('cpp', native: false).get_id() != 'msvc'
    error('Unsuitable compiler: this subproject requires Microsoft Visual Studio only')
endif

if host_machine.cpu_family() == 'x86_64'
    folder = 'x64'
elif host_machine.cpu_family() == 'aarch64'
    folder = 'ARM64'
elif host_machine.cpu_family() == 'x86'
    folder = 'x86'
else
    error('Unsuitable architecture: this subproject requires x86, x86_64 or aarch64 only')
endif

depdutil = subproject('dutil').get_variable('depdutil')

depwcautil = declare_dependency(
    include_directories: 'build' / 'native' / 'include',
    dependencies: [
        meson.get_compiler('cpp').find_library('wcautil', dirs: meson.project_source_root() / 'build' / 'native' / 'v14' / folder),
        depdutil
    ]
)

