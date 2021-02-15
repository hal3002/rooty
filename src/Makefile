linux:
	gcc -DDEBUG -ggdb -o rooty rooty_unix.c rooty.c -lpcap -lpthread -I/usr/src/libexec/rtld-elf -I/usr/src/libexec/rtld-elf/amd64
windows:
	i586-mingw32msvc-g++ -DDEBUG -o rooty.exe rooty_win.c rooty.c -lws2_32
clean:
	rm -f *.o rooty.exe rooty
freebsd:
	gcc -o rooty rooty_unix.c rooty.c -O2 -fno-strict-aliasing -fdiagnostics-show-option -static -Wall -Wwrite-strings -Wformat -Wextra -Wformat-security -Wsign-compare -Wcast-align -Wno-unused-parameter -lpcap
	strip rooty
freebsd-debug:
	gcc -DDEBUG -o rooty rooty_unix.c rooty.c -O2 -fno-strict-aliasing -fdiagnostics-show-option -static -Wall -Wwrite-strings -Wformat -Wextra -Wformat-security -Wsign-compare -Wcast-align -Wno-unused-parameter -lpcap
