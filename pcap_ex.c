// 
//  Systems and Services Security PLH519
//      Network Traffic Monitoring
// 

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>
#include <pcap.h>

#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#define LOG_FILE "log.txt"
#define MAX_PACKET_SIZE 65535
#define TIMEOUT 500
#define MAX_FILTER_LENGTH 30

// Declaring global counters
int total_packets = 0;

int total_udp_packets = 0;
int total_tcp_packets = 0;
int total_network_flows = 0;

int tcp_network_flows = 0;
int udp_network_flows = 0;

int total_bytes_tcp = 0;
int total_bytes_udp = 0;

// If 0 print in console, 1 save in file
int store_flag = 0;

// Filter expression
char filter_exp[MAX_FILTER_LENGTH]; 

// Flag for filter activation
int apply_filter = 0;

enum protocol{
	UDP,
	TCP
};

struct networkFlow {
	char *source_ip;
	char *destination_ip;

	int source_port;
	int destination_port;

	enum protocol type;

	struct networkFlow *next;
};

// Init the network list, pointer to struct!
struct networkFlow *network = NULL;

/// @brief Prints all the data of the packet
void printPacketInfo(int packets, int version, char *src_ip, char *dst_ip, int src_port, int dst_port, enum protocol type, int header_len, int payload){

	if(store_flag == 0){

		printf("\tPacket Number: %d\n", packets);				
		printf(" [->] IP Version: 	 IPv%d\n", version);
		printf(" [->] Source IP: 	 %s\n", src_ip);
		printf(" [->] Destination IP: 	 %s\n", dst_ip);

		printf(" [->] Source Port: 	 %d\n", src_port);
		printf(" [->] Destination Port:  %d\n", dst_port);	

		if(type == TCP)
			printf(" [->] Protocol: 	 TCP\n");
		else
			printf(" [->] Protocol: 	 UDP\n");
			
		printf(" [->] Header Length:     %d\n", header_len);
		printf(" [->] Payload:		 %d\n", payload);
	}
	else {

		FILE *file = fopen(LOG_FILE, "a+");
		fprintf(file, "\tPacket Number: %d\n", packets);				
		fprintf(file, " [->] IP Version: 	 	 IPv%d\n", version);
		fprintf(file, " [->] Source IP: 	 	 %s\n", src_ip);
		fprintf(file, " [->] Destination IP: 	 %s\n", dst_ip);

		fprintf(file, " [->] Source Port: 	 	 %d\n", src_port);
		fprintf(file, " [->] Destination Port:  %d\n", dst_port);	

		if(type == TCP)
			fprintf(file, " [->] Protocol: 	 	 TCP\n");
		else
			fprintf(file, " [->] Protocol: 	 	 UDP\n");
			
		fprintf(file, " [->] Header Length:     %d\n", header_len);
		fprintf(file, " [->] Payload:		 	 %d\n", payload);

		fclose(file);
	}

	return;
}

/// @brief Print the statistics, aka global counters 
void statistics(void){
	printf(" +------------------------------------------------+\n");
	printf(" |                  Statistics                    |\n");
	printf(" +------------------------------------------------+\n");
	printf(" [->] Total network flows captured: 	   %d\n", total_network_flows);
	printf(" [->] Total TCP network flows captured:    %d\n", tcp_network_flows);
	printf(" [->] Total UDP network flows captured:    %d\n", udp_network_flows);
	printf(" [->] Total packets captured: 		   %d\n", total_packets);
	printf(" [->] Total TCP packets captured: 	   %d\n", total_tcp_packets);
	printf(" [->] Total UDP packets captured:          %d\n", total_udp_packets);
	printf(" [->] Total bytes of TCP packets captured: %d\n", total_bytes_tcp);
	printf(" [->] Total bytes of UDP packets captured: %d\n", total_bytes_udp);
	printf("\n");
	return;
}


void usage(void){
    printf(
	       "\n"
	       "Usage:\n\n"
		   "Options:\n"
		   "-i <interface>, Network interface name \n"
		   "-r <filename>, Packet capture file name\n"
           "-f <filter>, Filter expression\n"
		   "-h, Help message\n\n"
		   "e.g ./pcap_ex -r filename\n"
		   "e.g sudo ./pcap_ex -i enp0s3\n"
		   "e.g sudo ./pcap_ex -i enp0s3 -f 'port 8080' \n"
		  );
	
    exit(-1);
}

/// @brief Get a substring for a string
/// @param filter 
/// @param value 
/// @return the parsed string
void parseFilter(char *filter, char *value, int offset){
	strncpy(value, filter+offset, sizeof(value));
	return;
}


/// @brief Checks if a string contains a substring
/// @param str 
/// @param substr 
/// @return True if it contains, false otherwise
bool checkSubstring(char *str, char *substr){
	bool isPresent = false;
    for (int i = 0; str[i] != '\0'; i++) {
        isPresent = false;
        for (int j = 0; substr[j] != '\0'; j++) {
            if (str[i + j] != substr[j]) {
                isPresent = false;
                break;
            }
            isPresent = true;
        }
        if (isPresent) {
            return true;
        }
    }
	return false;
}


/// @brief Free the network flow list
void freeList(void){
	
	struct networkFlow *current = network;

	while(current != NULL){
		struct networkFlow *temp = current;
		current = current->next;
		free(temp);
	}	
	free(current);
	return;
}


/// @brief Checks if a networkFlow already exists in list -> retransmmited!
/// @return 1 if exists 0 otherwise
int checkExistance(char *src_ip, char *dst_ip, int src_port, int dst_port, enum protocol prot_type){

	// If list is empty, the current net doesnt exist!
	if(network == NULL)
		return 0;
	
	// Create a temp struct to search and compare
	struct networkFlow *temp = network;
	
	while(temp != NULL){
		
		if(strcmp(temp->source_ip, src_ip) == 0 && strcmp(temp->destination_ip, dst_ip) == 0 && temp->source_port == src_port 
			&& temp->destination_port == dst_port && temp->type == prot_type){
			// The packet is being retransmitted and already exists in list
			return 1;
		}

		// Move on!
		temp = temp->next;	
	}
	
	return 0;
}


/// @brief Creates a new netflow and add it to list
void createNetflow(char *src_ip, char *dst_ip, int src_port, int dst_port, enum protocol prot_type, int ip_length){
	
	total_network_flows++;

	if(prot_type == TCP){
		tcp_network_flows++;
	}
	else
		udp_network_flows++;

	if(network == NULL){
		network = (struct networkFlow *)malloc(sizeof(struct networkFlow));
		
		// Declare space for ips
		network->source_ip = (char *)malloc(ip_length);
		network->destination_ip = (char *)malloc(ip_length);
		
		// Fill the struct variables
		network->source_ip = src_ip;
		network->destination_ip = dst_ip;

		network->source_port = src_port;
		network->destination_port = dst_port;

		network->type = prot_type;

		// Points to NULL
		network->next = NULL;
	}

	// If the list is not empty, go to the end of the list and add the new flow
	struct networkFlow *new = (struct networkFlow *)malloc(sizeof(struct networkFlow));

	// Set a temp pointer to find the end
	struct networkFlow *temp = network;

	// Traverse
	while(temp->next != NULL){
		temp = temp->next;
	}

	// Set the next to the new struct instead of null
	temp->next = new;

	// link done! Now fill the variables
	new->source_ip = (char *)malloc(ip_length);
	new->destination_ip = (char *)malloc(ip_length);

	new->source_ip = src_ip;
	new->destination_ip = dst_ip;

	new->source_port = src_port;
	new->destination_port = dst_port;

	new->type = prot_type;
	new->next = NULL;

	return;
}


/// @brief Callback function invoked by libpcap for every incoming packet
void packet_handler(u_char *user, const struct pcap_pkthdr *pkt_header, const u_char *pkt_data){

	// Variables to check for filter apply
	int port = -1;
	int s_port = -1;
	int d_port = -1;
	int ip_ver = -1;
	int protocol = -1;
	char *ip = NULL;
	char *s_ip = NULL;
	char *d_ip = NULL;
	
	int capture_flag = 0;

	if(apply_filter == 1){
		// Check each case
		if(checkSubstring(filter_exp, "src port ") && capture_flag == 0){
			char *portNum = (char *)malloc(sizeof(strlen(filter_exp) - 9));
			parseFilter(filter_exp, portNum, 9);
			s_port = atoi(portNum);
			capture_flag = 1;
		}

		if(checkSubstring(filter_exp, "dst port ") && capture_flag == 0){
			char *portNum = (char *)malloc(sizeof(strlen(filter_exp) - 9));
			parseFilter(filter_exp, portNum, 9);
			d_port = atoi(portNum);
			capture_flag = 1;
		}

		if(checkSubstring(filter_exp, "port ") && capture_flag == 0){
			char *portNum = (char *)malloc(sizeof(strlen(filter_exp) - 5));
			parseFilter(filter_exp, portNum, 5);
			port = atoi(portNum);
			capture_flag = 1;
		}

		if(checkSubstring(filter_exp, "src ip ") && capture_flag == 0){
			char *ip_addr = (char *)malloc(sizeof((strlen(filter_exp) - 7)));
			strcpy(ip_addr, filter_exp + 7);
			// s_ip = (char *)malloc(sizeof((strlen(filter_exp) - 7)));
			s_ip = ip_addr;
			// printf("Output: %s\n", s_ip);
			capture_flag = 1;
		}

		if(checkSubstring(filter_exp, "dst ip ") && capture_flag == 0){
			char *ip_daddr = (char *)malloc(sizeof((strlen(filter_exp) - 7)));
			strcpy(ip_daddr, filter_exp + 7);
			// s_ip = (char *)malloc(sizeof((strlen(filter_exp) - 7)));
			d_ip = ip_daddr;
			// printf("Output: %s\n", d_ip);
			capture_flag = 1;
		}

		if(checkSubstring(filter_exp, "ip version ") && capture_flag == 0){
			char *ip_version = (char *)malloc(sizeof(strlen(filter_exp) - 11));
			parseFilter(filter_exp, ip_version, 11);
			ip_ver = atoi(ip_version);
			if(ip_ver == 4){
				ip_ver = ETHERTYPE_IP;
			}
			else if(ip_ver == 6){
				ip_ver = ETHERTYPE_IPV6;
			}
			else{
				printf("No such version of IP\n");
				exit(-1);
			}
			// printf("Version is: %d\n", ip_ver);
			capture_flag = 1;
		}

		if(checkSubstring(filter_exp, "ip ") && capture_flag == 0){
			char *ip_addr = (char *)malloc(sizeof((strlen(filter_exp) - 3)));
			strcpy(ip_addr, filter_exp + 3);
			// s_ip = (char *)malloc(sizeof((strlen(filter_exp) - 7)));
			ip = ip_addr;
			// printf("Output: %s\n", d_ip);
			capture_flag = 1;
		}

		if(checkSubstring(filter_exp, "protocol ") && capture_flag == 0){
			char *prot = (char *)malloc(sizeof((strlen(filter_exp) - 9)));
			strcpy(prot, filter_exp + 9);
			// s_ip = (char *)malloc(sizeof((strlen(filter_exp) - 7)));
			if(strcmp(prot, "TCP") == 0){
				protocol = IPPROTO_TCP;
			}
			else if(strcmp(prot, "UDP") == 0){
				protocol = IPPROTO_UDP;
			}
			else{
				printf("No such protocol supported!\n");
				exit(-1);
			}
			// printf("Output: %s\n", s_ip);
			capture_flag = 1;
		}

	}

	/* Simply step by step construct ethernet frame*/

	// Init ethernet structure to get IPV4 or IPV6 version
	struct ethhdr *eth_header = (struct ethhdr *)(pkt_data);
	
	int frame_size = 0;

	if(eth_header == NULL)
		exit(EXIT_FAILURE);

	// Got a packet
	total_packets++;
	
	// Check for IPv4 or IPv6
	switch(ntohs(eth_header->h_proto)){ 

		case ETHERTYPE_IP:	//0x0800 -> IPv4

			if(apply_filter == 1){
				if(ip_ver != -1){
					if(ip_ver != ETHERTYPE_IP)
						break;
				}
			}

			// Init the ip header structure
			struct iphdr *ip_header = (struct iphdr *)(pkt_data + sizeof(struct ethhdr));
			
			// Increase frame size, so that later we can find tcp/udp length
			frame_size += sizeof(struct iphdr) + sizeof(struct ethhdr);

			// Get the ip header info
			char src_ip[INET_ADDRSTRLEN];
			char dst_ip[INET_ADDRSTRLEN];
				
			// Convert ip in string format and store
			inet_ntop(AF_INET, &(ip_header->saddr), src_ip, INET_ADDRSTRLEN);
			inet_ntop(AF_INET, &(ip_header->daddr), dst_ip, INET_ADDRSTRLEN);

			if(apply_filter == 1){
				if(s_ip != NULL){
					if(strcmp(s_ip, src_ip)!=0){
						free(s_ip);
						break;
					}
				}

				if(d_ip != NULL){
					if(strcmp(d_ip, dst_ip)!=0){
						free(d_ip);
						break;
					}
				}

				if(ip != NULL){
					if(strcmp(ip, src_ip) != 0 && strcmp(ip, dst_ip) != 0){
						free(ip);
						break;
					}
				}

			}


			// Check the protocol TPC/UDP
			switch(ip_header->protocol){
				
				case IPPROTO_TCP:

					if(apply_filter == 1){
						if(protocol != -1){
							if(protocol != IPPROTO_TCP)
								break;
						}
					}

					// Get the ports
					int tcp_src_port;
					int tcp_dst_port;

					// Now constuct the tcp_header
					struct tcphdr *tcp_header = (struct tcphdr *)(pkt_data + frame_size);

					tcp_src_port= ntohs(tcp_header->th_sport);
					tcp_dst_port = ntohs(tcp_header->th_dport);

					if(apply_filter == 1){	
						if(port != -1){
							if(tcp_src_port != port && tcp_dst_port != port) {
								break;
							}
						}

						if(s_port != -1){
							if(tcp_src_port != s_port)
								break;
						}
						

						if(d_port != -1){
							if(tcp_dst_port != d_port)
								break;
						}						
					}
					
					// Increase frame size by the data amount to calc payload
					frame_size += sizeof(struct tcphdr);
					
					int tcp_payload = pkt_header->len - frame_size; //data remains

					printPacketInfo(total_packets, 4, src_ip, dst_ip, tcp_src_port, tcp_dst_port, TCP, (int)sizeof(struct tcphdr), tcp_payload);

					// Here create a new net flow
					if(!checkExistance(src_ip, dst_ip, tcp_src_port, tcp_dst_port, TCP)){
						//create the struct
						createNetflow(src_ip, dst_ip, tcp_src_port, tcp_dst_port, TCP, INET_ADDRSTRLEN);
						if(store_flag == 0)
							printf("\n");
						else{
							FILE *file = fopen(LOG_FILE, "a+");
							fprintf(file, "\n");
							fclose(file);
						}
					}
					else{
						if(store_flag == 0)
							printf(" [->] TCP Retransmission\n\n");
						else{
							FILE *file = fopen(LOG_FILE, "a+");
							fprintf(file, " [->] TCP Retransmission\n\n");
							fclose(file);
						}
					}

					// increase the tcp bytes += payload!
					total_bytes_tcp += tcp_payload + frame_size; // total payload or all total packet???
					total_tcp_packets++;
					break;

				case IPPROTO_UDP:

					if(apply_filter == 1){
						if(protocol != -1){
							if(protocol != IPPROTO_UDP)
								break;
						}
					}					

					// Get the ports
					int udp_src_port;
					int udp_dst_port;

					// Now constuct the udp_header
					struct udphdr *udp_header = (struct udphdr *)(pkt_data + frame_size);

					udp_src_port= ntohs(udp_header->uh_sport);
					udp_dst_port = ntohs(udp_header->uh_dport);
					
					if(apply_filter == 1){					
						if(port != -1){
							if(udp_src_port != port && udp_dst_port != port)
								break;
						}
						
						if(s_port != -1){
							if(udp_src_port != s_port)
								break;
						}

						if(d_port != -1){
							if(udp_dst_port != d_port)
								break;
						}	
					}				

					// Increase frame size by the data amount to calc payload
					frame_size += sizeof(struct udphdr);
					
					int udp_payload = pkt_header->len - frame_size;

					printPacketInfo(total_packets, 4, src_ip, dst_ip, udp_src_port, udp_dst_port, UDP, (int)sizeof(struct udphdr), udp_payload);

					// Here create a new net flow
					if(!checkExistance(src_ip, dst_ip, udp_src_port, udp_dst_port, UDP)){
						//create the struct
						createNetflow(src_ip, dst_ip, udp_src_port, udp_dst_port, UDP, INET_ADDRSTRLEN);
						if(store_flag == 0)
							printf("\n");
						else{
							FILE *file = fopen(LOG_FILE, "a+");
							fprintf(file, "\n");
							fclose(file);
						}
					}

					total_bytes_udp += udp_payload + frame_size; // total payload or all total packet???
					total_udp_packets++;
					break;

				default:
					//Skip!
					break;
			}

			break;

		case ETHERTYPE_IPV6: //0x860d

			if(apply_filter == 1){
				if(ip_ver != -1){
					if(ip_ver != ETHERTYPE_IPV6)
						break;
				}
			}

			struct ip6_hdr *ip6_header = (struct ip6_hdr *)(pkt_data + sizeof(struct ethhdr));

			frame_size += sizeof(struct ip6_hdr) + sizeof(struct ethhdr);

			// Get the ip header info
			char src_ip6[INET6_ADDRSTRLEN];
			char dst_ip6[INET6_ADDRSTRLEN];
				
			// Convert ip in string format and store
			inet_ntop(AF_INET6, &(ip6_header->ip6_src), src_ip6, INET6_ADDRSTRLEN);
			inet_ntop(AF_INET6, &(ip6_header->ip6_dst), dst_ip6, INET6_ADDRSTRLEN);

			if(apply_filter == 1){
				if(s_ip != NULL){
					if(strcmp(s_ip, src_ip6)!=0){
						free(s_ip);
						break;
					}
				}
				
				if(d_ip != NULL){
					if(strcmp(d_ip, dst_ip6)!=0){
						free(d_ip);
						break;
					}
				}

				if(ip != NULL){
					if(strcmp(ip, src_ip6) != 0 && strcmp(ip, dst_ip6) != 0){
						free(ip);
						break;
					}
				}
			}	

			// Check the protocol TPC/UDP
			switch(ip6_header->ip6_nxt){		// Line 45 in ip6.h
				
				case IPPROTO_TCP:

					if(apply_filter == 1){
						if(protocol != -1){
							if(protocol != IPPROTO_TCP)
								break;
						}
					}	

					// Get the ports
					int tcp_src_port;
					int tcp_dst_port;

					// Now constuct the tcp_header
					struct tcphdr *tcp_header = (struct tcphdr *)(pkt_data + frame_size);

					tcp_src_port= ntohs(tcp_header->th_sport);
					tcp_dst_port = ntohs(tcp_header->th_dport);

					if(apply_filter == 1){			
						if(port != -1){
							if(tcp_src_port != port && tcp_dst_port != port)
								break;
						}

						if(s_port != -1){
							if(tcp_src_port != s_port)
								break;
						}

						if(d_port != -1){
							if(tcp_dst_port != d_port)
								break;
						}
					}

					// Increase frame size by the data amount to calc payload
					frame_size += sizeof(struct tcphdr);
					
					int tcp_payload = pkt_header->len - frame_size; //data remains

					printPacketInfo(total_packets, 6, src_ip6, dst_ip6, tcp_src_port, tcp_dst_port, TCP, (int)sizeof(struct tcphdr), tcp_payload);

					// Here create a new net flow
					if(!checkExistance(src_ip6, dst_ip6, tcp_src_port, tcp_dst_port, TCP)){
						//create the struct
						createNetflow(src_ip6, dst_ip6, tcp_src_port, tcp_dst_port, TCP, INET6_ADDRSTRLEN);
						if(store_flag == 0)
							printf("\n");
						else{
							FILE *file = fopen(LOG_FILE, "a+");
							fprintf(file, "\n");
							fclose(file);
						}
					}
					else {
						if(store_flag == 0)
							printf(" [->] TCP Retransmission\n\n");
						else{
							FILE *file = fopen(LOG_FILE, "a+");
							fprintf(file, " [->] TCP Retransmission\n\n");
							fclose(file);
						}
					}

					total_bytes_tcp += tcp_payload + frame_size; // total payload or all total packet???
					total_tcp_packets++;	
					break;

				case IPPROTO_UDP:

					if(apply_filter == 1){
						if(protocol != -1){
							if(protocol != IPPROTO_UDP)
								break;
						}
					}	

					// Get the ports
					int udp_src_port;
					int udp_dst_port;

					// Now constuct the udp_header
					struct udphdr *udp_header = (struct udphdr *)(pkt_data + frame_size);

					udp_src_port= ntohs(udp_header->uh_sport);
					udp_dst_port = ntohs(udp_header->uh_dport);

					if(apply_filter == 1){
						
						if(port != -1){
							if(udp_src_port != port && udp_dst_port != port) {
								break;
							}
						}

						if(s_port != -1){
							if(udp_src_port != s_port)
								break;
						}

						if(d_port != -1){
							if(udp_dst_port != d_port)
								break;
						}


					}

					// Increase frame size by the data amount to calc payload
					frame_size += sizeof(struct udphdr);
					
					int udp_payload = pkt_header->len - frame_size;

					printPacketInfo(total_packets, 6, src_ip6, dst_ip6, udp_src_port, udp_dst_port, UDP, (int)sizeof(struct udphdr), udp_payload);

					// Here create a new net flow
					if(!checkExistance(src_ip6, dst_ip6, udp_src_port, udp_dst_port, UDP)){
						//create the struct
						createNetflow(src_ip6, dst_ip6, udp_src_port, udp_dst_port, UDP, INET6_ADDRSTRLEN);
						if(store_flag == 0)
							printf("\n");
						else{
							FILE *file = fopen(LOG_FILE, "a+");
							fprintf(file, "\n");
							fclose(file);
						}
					}

					total_bytes_udp += udp_payload + frame_size; // total payload or all total packet???
					total_udp_packets++;
					// exit(-1); -> to stop at IPv6 packet
					break;

				default:
					printf("Not a UDP or TCP packet!\n");
					//Skip!
					break;
			}

			break;
		
		default:
			// Other packet, skip!
			break;
	}

	return;
}


/// @brief This function will read the traffic from the file
void offline_monitor(char *filename){

	if(filename == NULL){
		printf("Filename is NULL!\n");
		exit(-1);
	}

	// Just a buf to report the error
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *read_packets = NULL;

	// Open a savefile in the tcpdump/libpcap format to read packets.
	read_packets = pcap_open_offline(filename, errbuf);

	if(read_packets == NULL){
		printf("%s\n", errbuf);
		exit(-1);
	}
	
	// Now that we have opened the file, read the packets and parse information
	// A value of -1 or 0 for cnt is equivalent to infinity, so that packets are processed until another ending condition occurs.
	int returnVal = pcap_loop(read_packets, 0, &packet_handler, NULL);

	if(returnVal == -1)
		exit(-1);

	// Close the opened file
	pcap_close(read_packets);

	// The statistics function can be placed here! pcap_loop will loop again and again until it reach EOF
	statistics();

	// Free the list
	freeList();

	return;
}


/// @brief This function will start capturing traffic from a network interface
void online_monitor(char *interface){

	// Set store flag to 1
	store_flag = 1;

	if(interface == NULL){
		printf("Filename is NULL!\n");
		exit(-1);
	}
	char errbuf[PCAP_ERRBUF_SIZE];

	// check if interface is valid!
	pcap_if_t *alldevsp;
	int existance_flag = 0;
	if(!pcap_findalldevs(&alldevsp, errbuf)){ 		//enp0s3 in ubuntu/vm
		pcap_if_t *dev = alldevsp;
		while(dev != NULL){
			if(strcmp(interface, dev->name) == 0){
				existance_flag = 1;
			}
			dev = dev->next;
		}
		if(!existance_flag){
			printf("No such interface!\n");
			usage();
			// exit(-1);
		}
	}

	// https://www.tcpdump.org/manpages/pcap_open_live.3pcap.html
	// Just a buf to report the error
	pcap_t *read_packets = NULL;

	read_packets = pcap_open_live(interface, MAX_PACKET_SIZE, 1, TIMEOUT, errbuf);
	
	if(read_packets == NULL){
		printf("%s\n", errbuf);
		exit(-1);
	}
	
	// Just to check
	// char filter_exp[] = "src host 10.0.2.15";
	// struct bpf_program fp;

  	// Compile and apply the filter
  	// if(pcap_compile(read_packets, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
    // 	fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(read_packets));
    // 	exit(-1);
	// }
  	// if(pcap_setfilter(read_packets, &fp) == -1) {
    // 	fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(read_packets));
    // 	exit(-1);
 	// }

	// Now that we have opened the file, read the packets and parse information
	// A value of -1 or 0 for cnt is equivalent to infinity, so that packets are processed until another ending condition occurs.
	int returnVal = pcap_loop(read_packets, TIMEOUT, &packet_handler, NULL);

	if(returnVal == -1)
		exit(-1);

	// Close the opened file
	pcap_close(read_packets);

	// Free list of devices
	pcap_freealldevs(alldevsp);
	
	// The statistics function can be placed here! pcap_loop will loop again and again until it reach EOF
	statistics();

	// Free the list
	freeList();

	return;
}

/// @brief Main func of the program
/// @param argc 
/// @param argv 
/// @return 0 on success
int main(int argc, char *argv[])
{
    int ch;
    while((ch = getopt(argc, argv, "hr:i:f:")) != -1) {
	    switch(ch) {		
		    case 'i':
				if(argc == 4)
					usage();
				else if(argc == 3){
					printf("Listening....\n\n");
					online_monitor(optarg);
					printf("Timeout expired! Look at log.txt\n");
				}
				else{
					remove(LOG_FILE);
					printf("Listening....\n");
					printf("Filter expression: <%s>\n", argv[4]);
					strcpy(filter_exp, argv[4]);
					apply_filter = 1;
					online_monitor(optarg);
					printf("Timeout expired! Look at log.txt\n");
				}
			    break;
		    case 'r': 
				apply_filter = 0;
				offline_monitor(optarg);
    			break;
			case 'f':
				break;
	    	case 'h':   
		        usage();
		        break;
	    	default:
		    	usage();
		}
	}

    argc -= optind;
    argv += optind;

    return 0;
}