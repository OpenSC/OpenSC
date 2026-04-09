project('dutil', 'cpp')

if meson.get_compiler('cpp', native: false).get_id() != 'msvc'
    error('Unsuitable compiler: this subproject requires Microsoft Visual Studio only')
endif

cc = meson.get_compiler('cpp')
if cc.get_define('_M_ARM64') != ''
    folder = 'ARM64'
elif cc.get_define('_M_AMD64') != ''
    folder = 'x64'
elif cc.get_define('_M_IX86') != ''
    folder = 'x86'
else
    error('Unsuitable architecture: this subproject requires x86, x86_64 or aarch64 only')
endif

depdutil = declare_dependency(
  include_directories: 'build' / 'native' / 'include',
  dependencies: meson.get_compiler('cpp').find_library('dutil', dirs: meson.project_source_root() / 'build' / 'native' / 'v14' / folder)
)

