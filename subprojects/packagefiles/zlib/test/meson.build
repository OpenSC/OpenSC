if get_option('tests').disabled()
  subdir_done()
endif

test(
  'example',
  executable(
    'example',
    'example.c',
    dependencies: zlib_dep,
    build_by_default: false,
  ),
)
#test('minigzip', executable('minigzip', 'minigzip.c', dependencies: zlib_dep))
