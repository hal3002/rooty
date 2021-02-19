all:
	gcc -DDEBUG -ggdb -O0 -o rooty-debug rooty_unix.c rooty.c -lpcap -lpthread
	gcc -O2 -o rooty rooty_unix.c rooty.c -lpcap -lpthread
	cp rooty rooty-release
	strip rooty-release
clean:
	rm -f *.o rooty.exe rooty rooty-release rooty-debug
