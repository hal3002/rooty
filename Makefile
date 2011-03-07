CC = gcc -ggdb
LIBS = -L/usr/lib -lpcap -lpthread

all: rooty

rooty::
	$(CC) -o rooty rooty.c ${LIBS}

clean:
	rm -f rooty
