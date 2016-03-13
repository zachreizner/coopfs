project('coopfs', 'cpp')

add_global_arguments('-std=c++14', language : 'cpp')
add_global_arguments('-fdiagnostics-color', language : 'cpp')

incdir = include_directories('src')

sodiumdep = dependency('libsodium')
zmqdep = dependency('libzmq')


coopfstest = executable('coopfs_test',
    'src/keyvalue.cpp',
    'test/catch_main.cpp',
    'test/trivial.cpp',
    'test/keyvalue.cpp',
    cpp_args : '-Dgsl_CONFIG_THROWS_FOR_TESTING=1',
    include_directories : incdir,
    dependencies : [sodiumdep, zmqdep])
test('coopfs tests', coopfstest)

