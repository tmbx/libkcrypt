Import('env build_dir')

import os

lib_NAME = "libkcrypt"

main_env = env
main_env.Append(CCFLAGS = os.popen('libgcrypt-config --cflags', 'r').readline()[:-1].split(),
                LINKFLAGS = os.popen('libgcrypt-config --libs', 'r').readline()[:-1].split())
# build the lib
env = main_env.Clone()
env.Append(CPPPATH = [os.path.join(os.getcwd(), 'src'), os.path.join(os.getcwd(), '..', 'libktools', 'src')],
           VERSION = '3.0')
shared_LIBS, static_LIBS, OBJS, install = SConscript(os.path.join('src', 'SConscript'), build_dir=build_dir, duplicate=0, exports='env lib_NAME')

# build the test
PROGS = []
if env['test']:
    env = main_env.Clone()
    env.Append(CPPPATH=[os.path.join(os.getcwd(), 'test'), os.path.join(os.getcwd(), 'src'), os.path.join(os.getcwd(), '..', 'libktools', 'src')])

    #This is a hack as we should install libktools and use the installed version.
    env.Append(LIBPATH=os.path.join(os.getcwd(), '..', 'libktools', 'build'), LIBS='ktools')
    NOBJS, PROG = SConscript(os.path.join('test', 'SConscript'), build_dir=os.path.join(build_dir, 'test'), duplicate=0, exports='env shared_LIBS static_LIBS lib_NAME')
OBJS += NOBJS
PROGS += PROG

builds = OBJS + PROG + static_LIBS + shared_LIBS

Return('builds install')
