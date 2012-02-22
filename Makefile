.PHONY: all

all:
	scons

clean:
	scons -c

%:
	scons $(MAKECMDGOALS)

help:
	scons -h
