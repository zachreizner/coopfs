project('coopfs', 'cpp')

add_global_arguments('-std=c++14', language : 'cpp')

sodiumdep = dependency('libsodium')
zmqdep = dependency('libzmq')

coopfstest = executable('coopfs_test', 'test/catch_main.cpp',
    dependencies : [sodiumdep, zmqdep])
test('coopfs tests', coopfstest)

