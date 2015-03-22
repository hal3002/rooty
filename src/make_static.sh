#!/bin/bash

ARCH=x64

# I know there is a better way to do this but I currently don't care
rm rooty-debug.$ARCH
rm rooty-release.$ARCH
rm rooty-upx.$ARCH

gcc48 -DDEBUG -o rooty rooty_unix.c rooty.c -lhijack -lpcap -lpthread -I/usr/src/libexec/rtld-elf -I/usr/src/libexec/rtld-elf/amd64 -I/home/hal/libhijack/include
gcc48 -O2 -fno-strict-aliasing -Wall -Wwrite-strings -Wformat -fdiagnostics-show-option -Wextra -Wformat-security -Wsign-compare -Wcast-align -Wno-unused-parameter -DDEBUG -static -o rooty-debug.$ARCH rooty.c -lpcap libhijack.o error.o misc.o ptrace.o map.o elf.o func.o rtld.o os_resolv.o -lpcap -lpthread -I/usr/src/libexec/rtld-elf -I/usr/src/libexec/rtld-elf/amd64 -I/home/hal/libhijack/include
gcc48 -O2 -fno-strict-aliasing -Wall -Wwrite-strings -Wformat -fdiagnostics-show-option -Wextra -Wformat-security -Wsign-compare -Wcast-align -Wno-unused-parameter -static -o rooty-release.$ARCH rooty.c -lpcap libhijack.o error.o misc.o ptrace.o map.o elf.o func.o rtld.o os_resolv.o -lpcap -lpthread -I/usr/src/libexec/rtld-elf -I/usr/src/libexec/rtld-elf/amd64 -I/home/hal/libhijack/include

strip rooty-release.$ARCH
cp rooty-release.$ARCH rooty-upx.$ARCH
upx rooty-upx.$ARCH
