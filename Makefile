CC = gcc 
LIBS = -L/usr/lib -lpcap -lpthread
STRIP = strip
UPX = upx

all: rooty

rooty::
	$(CC) -static -o rooty rooty.c ${LIBS}
	${STRIP} rooty

debug::
	$(CC) -DDEBUG -ggdb -o rooty rooty.c ${LIBS}

upx:: rooty
	upx -9 rooty


clean:
	rm -f rooty
