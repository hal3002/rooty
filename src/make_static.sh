#!/bin/bash

ARCH=x86

# I know there is a better way to do this but I currently don't care
rm rooty-debug.$ARCH
rm rooty-release.$ARCH
rm rooty-upx.$ARCH

gcc -O2 -fno-strict-aliasing -Wall -Wwrite-strings -Wformat -fdiagnostics-show-option -Wextra -Wformat-security -Wsign-compare -Wcast-align -Wno-unused-parameter -pedantic -DDEBUG -static -o rooty-debug.$ARCH rooty.c -lpcap libhijack.o error.o misc.o ptrace.o map.o elf.o func.o rtld.o os_resolv.o
gcc -O2 -fno-strict-aliasing -Wall -Wwrite-strings -Wformat -fdiagnostics-show-option -Wextra -Wformat-security -Wsign-compare -Wcast-align -Wno-unused-parameter -pedantic -static -o rooty-release.$ARCH rooty.c -lpcap libhijack.o error.o misc.o ptrace.o map.o elf.o func.o rtld.o os_resolv.o

strip rooty-release.$ARCH
cp rooty-release.$ARCH rooty-upx.$ARCH
upx rooty-upx.$ARCH
