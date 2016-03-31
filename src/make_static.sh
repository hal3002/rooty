#!/bin/bash

# I know there is a better way to do this but I currently don't care
rm rooty-debug
rm rooty-release
rm rooty-upx

gcc -DDEBUG -o rooty rooty_unix.c rooty.c -lhijack -lpcap -lpthread -I/usr/src/libexec/rtld-elf -I/usr/src/libexec/rtld-elf/amd64 -I$HOME/libhijack/include
gcc -O2 -fno-strict-aliasing -Wall -Wwrite-strings -Wformat -fdiagnostics-show-option -Wextra -Wformat-security -Wsign-compare -Wcast-align -Wno-unused-parameter -DDEBUG -static -o rooty-debug rooty.c rooty_unix.c -lpcap libhijack.o error.o misc.o ptrace.o map.o elf.o func.o rtld.o os_resolv.o -lpcap -lpthread -I/usr/src/libexec/rtld-elf -I/usr/src/libexec/rtld-elf/amd64 -I$HOME/libhijack/include
gcc -O2 -fno-strict-aliasing -Wall -Wwrite-strings -Wformat -fdiagnostics-show-option -Wextra -Wformat-security -Wsign-compare -Wcast-align -Wno-unused-parameter -static -o rooty-release rooty.c rooty_unix.c -lpcap libhijack.o error.o misc.o ptrace.o map.o elf.o func.o rtld.o os_resolv.o -lpcap -lpthread -I/usr/src/libexec/rtld-elf -I/usr/src/libexec/rtld-elf/amd64 -I$HOME/libhijack/include



strip rooty-release
cp rooty-release rooty-upx
upx rooty-upx
