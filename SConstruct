#
# SConstruct
# Copyright (C) 2005-2012 Opersys inc., All rights reserved.
#

import commands, os, sys, re
from kenv import KEnvironment


# Per Laurent Birtz example.
EnsurePythonVersion(2,3)
#env.Decider()
#Decider('MD5')
#TargetSignatures('content')

lib_OPTIONS = Options('build.conf')
lib_OPTIONS.AddOptions(
    BoolOption('mudflap', 'Build with mudflap (gcc 4.x)', 0),
    BoolOption('mpatrol', 'Build with mpatrol', 0),
    BoolOption('debug', 'Compile with all debug options turned on', 1),
    BoolOption('test', 'Build test', 1),
    ('PREFIX', 'Base directory to install the lib', '/usr/local'),
    ('LIBDIR', 'Directory to install library files', '$PREFIX/lib'),
    ('INCDIR', 'Directory where to install the header files', '$PREFIX/include')
)

# Setup the build environment.
env = KEnvironment(options = lib_OPTIONS)
lib_OPTIONS.Save('build.conf', env)

# Generate the help text.
Help(lib_OPTIONS.GenerateHelpText(env))

# build the lib
build_dir = os.path.join(os.getcwd(), 'build')
builds, install = SConscript('SConscript', duplicate = 0, exports='env build_dir')

# install
install.append(env.Dir(name=env['LIBDIR']))
install.append(env.Dir(name=env['INCDIR']))
env.Alias('install', install)

# clean
if 'clean' in COMMAND_LINE_TARGETS:
    SetOption("clean", 1)
    Alias("clean", builds)
