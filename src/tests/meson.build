base64 = executable('base64', 'base64.c', 'sc-test.c',
    include_directories: core_inc,
    link_with: [opensc_lib],
    )

lottery = executable('lottery', 'lottery.c', 'sc-test.c',
    include_directories: core_inc,
    link_with: [opensc_lib],
    )

p15dump  = executable('p15dump', 'p15dump.c', 'print.c', 'sc-test.c',
    include_directories: core_inc,
    link_with: [opensc_lib],
    )

pintest  = executable('pintest', 'pintest.c', 'print.c', 'sc-test.c',
    include_directories: core_inc,
    link_with: [opensc_lib],
    )

prngtest  = executable('prngtest', 'prngtest.c', 'sc-test.c',
    include_directories: core_inc,
    link_with: [opensc_lib],
    )
