#include "rooty.h"

#ifndef UNICODE
#define UNICODE
#endif

#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <winsock2.h>
#pragma comment(lib,"ws2_32.lib")

#define SIO_RCVALL _WSAIOW(IOC_VENDOR,1)

typedef struct ip_hdr {
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

typedef struct icmp_hdr {
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
      uint16_t   __unused;
      uint16_t   mtu;
    } frag;       /* path mtu discovery */
  } un;
} ICMP_HDR;

uint32_t sniffer_loop(SOCKET *s);
uint32_t process_packet(const uint8_t *buffer, uint32_t len);
void hexdump(const char *buffer, uint32_t size);
