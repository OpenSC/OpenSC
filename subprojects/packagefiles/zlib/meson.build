project(
  'zlib',
  'c',
  version: '1.3.2',
  license: 'Zlib',
  meson_version: '>=0.56.0',
)

cc = meson.get_compiler('c')

link_args = cc.get_supported_link_arguments(
  '-Wl,--version-script,@0@/zlib.map'.format(meson.current_source_dir()),
)

if cc.get_argument_syntax() == 'msvc'
  add_project_arguments(
    '-D_CRT_SECURE_NO_DEPRECATE',
    '-D_CRT_NONSTDC_NO_DEPRECATE',
    language: 'c',
  )
endif

add_project_arguments(
  '-D_LARGEFILE64_SOURCE',
  language: 'c',
)

src = files(
  'adler32.c',
  'crc32.c',
  'deflate.c',
  'infback.c',
  'inffast.c',
  'inflate.c',
  'inftrees.c',
  'trees.c',
  'zutil.c',
)

headers = files('zconf.h', 'zlib.h')

if host_machine.system() == 'windows'
  win = import('windows')
  win_args = []
  if cc.get_argument_syntax() != 'msvc'
    win_args += '-DGCC_WINDRES'
  endif
  src += win.compile_resources(
    'win32/zlib1.rc',
    args: win_args,
  )
endif

solo_args = []
if get_option('solo')
  if host_machine.system() == 'windows' and get_option('default_library') != 'static'
    error('-Dsolo=true is incompatible with building a DLL')
  endif
  solo_args = ['-DZ_SOLO']
  add_project_arguments(
    solo_args,
    language: 'c',
  )
else
  src += files(
    'compress.c',
    'gzclose.c',
    'gzlib.c',
    'gzread.c',
    'gzwrite.c',
    'uncompr.c',
  )
endif

zlib = library(
  'z',
  src,
  link_args: link_args,
  vs_module_defs: 'win32/zlib.def',
  install: true,
  version: meson.project_version(),
)

depinc = include_directories('.')
zlib_dep = declare_dependency(
  compile_args: solo_args,
  link_with: zlib,
  include_directories: depinc,
)
meson.override_dependency('zlib', zlib_dep)

install_headers(headers)

pkg = import('pkgconfig')

pkg.generate(
  zlib,
  name: 'zlib',
  description: 'zlib compression library',
  extra_cflags: solo_args,
)

subdir('test')
