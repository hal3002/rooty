#!/bin/bash

# I know there is a better way to do this but I currently don't care
rm rooty-debug
rm rooty-release
rm rooty-upx

gcc -DDEBUG -static -o rooty-debug rooty_unix.c rooty.c -lpcap -lpthread
gcc -static -o rooty-release rooty_unix.c rooty.c -lpcap -lpthread

strip rooty-release
#cp rooty-release rooty-upx
#upx rooty-upx
