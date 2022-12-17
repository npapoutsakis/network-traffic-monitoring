#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pcap.h>

#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>


// Declaring global counters
int total_packets = 0;

int total_udp_packets = 0;
int total_tcp_packets = 0;
int total_network_flows = 0;

int tcp_network_flows = 0;
int udp_network_flows = 0;

int total_bytes_tcp = 0;
int total_bytes_udp = 0;

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


/// @brief Print the statistics, aka global counters 
void statistics(void){
	printf(" +----------------------------------------------+\n");
	printf(" |                  Statistics                  |\n");
	printf(" +----------------------------------------------+\n");
	printf(" [->] Total network flows captured: %d\n", total_network_flows);
	printf(" [->] Total TCP network flows captured: %d\n", tcp_network_flows);
	printf(" [->] Total UDP network flows captured: %d\n", udp_network_flows);
	printf(" [->] Total packets captured: %d\n", total_packets);
	printf(" [->] Total TCP packets captured: %d\n", total_tcp_packets);
	printf(" [->] Total UDP packets captured: %d\n", total_udp_packets);
	printf(" [->] Total bytes of TCP packets captured: %d\n", total_bytes_tcp);
	printf(" [->] Total bytes of UDP packets captured: %d\n", total_bytes_udp);
	return;
}


/// @brief Creates a new netflow and add it to list
void createNetflow(struct networkFlow *head, char *src_ip, char *dst_ip, int src_port, int dst_port, enum protocol type){



	return;
}

/// @brief Callback function invoked by libpcap for every incoming packet
void packet_handler(u_char *user, const struct pcap_pkthdr *pkt_header, const u_char *pkt_data){

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

			// Check the protocol TPC/UDP
			switch(ip_header->protocol){
				
				case IPPROTO_TCP:
					printf("\tPacket Number: %d\n", total_packets);				
					printf(" [->] IP Version: 	 IPv4\n");
					printf(" [->] Source IP: 	 %s\n", src_ip);
					printf(" [->] Destination IP: 	 %s\n", dst_ip);
					
					// Get the ports
					int tcp_src_port;
					int tcp_dst_port;

					// Now constuct the tcp_header
					struct tcphdr *tcp_header = (struct tcphdr *)(pkt_data + frame_size);

					tcp_src_port= ntohs(tcp_header->th_sport);
					tcp_dst_port = ntohs(tcp_header->th_dport);

					printf(" [->] Source Port: 	 %d\n", tcp_src_port);
					printf(" [->] Destination Port:  %d\n", tcp_dst_port);

					// Increase frame size by the data amount to calc payload
					frame_size += sizeof(struct tcphdr);
					
					int tcp_payload = pkt_header->len - frame_size; //data remains

					printf(" [->] Protocol: 	 TCP\n");
					printf(" [->] Header Length:     %d\n", (int)sizeof(struct tcphdr));
					printf(" [->] Payload:		 %d\n\n", tcp_payload);

					// Here create a new net flow

					// increase tcp net counter if net doesnt exist

					// if doesnt exists, increase net total counter

					// increase the tcp bytes += payload!
					total_bytes_tcp += tcp_payload + frame_size; // total payload or all total packet???
					total_tcp_packets++;
					break;

				case IPPROTO_UDP:
					printf("\tPacket Number: %d\n", total_packets);				
					printf(" [->] IP Version: 	 IPv4\n");
					printf(" [->] Source IP:  	 %s\n", src_ip);
					printf(" [->] Destination IP: 	 %s\n", dst_ip);

					// Get the ports
					int udp_src_port;
					int udp_dst_port;

					// Now constuct the tcp_header
					struct udphdr *udp_header = (struct udphdr *)(pkt_data + frame_size);

					udp_src_port= ntohs(udp_header->uh_sport);
					udp_dst_port = ntohs(udp_header->uh_dport);

					printf(" [->] Source Port: 	 %d\n", udp_src_port);
					printf(" [->] Destination Port:  %d\n", udp_dst_port);

					// Increase frame size by the data amount to calc payload
					frame_size += sizeof(struct udphdr);
					
					int udp_payload = pkt_header->len - frame_size;

					printf(" [->] Protocol: 	 UDP\n");
					printf(" [->] Header Length:     %d\n", (int)sizeof(struct udphdr));
					printf(" [->] Payload:		 %d\n\n", udp_payload);

					// Here create a new net flow

					total_bytes_udp += udp_payload + frame_size; // total payload or all total packet???
					total_udp_packets++;
					break;

				default:
					//Skip!
					break;
			}

			break;

		case ETHERTYPE_IPV6:

			struct ip6_hdr *ip6_header = (struct ip6_hdr *)(pkt_data + sizeof(struct ethhdr));

			frame_size += sizeof(struct ip6_hdr) + sizeof(struct ethhdr);

			// Get the ip header info
			char src_ip6[INET6_ADDRSTRLEN];
			char dst_ip6[INET6_ADDRSTRLEN];
				
			// Convert ip in string format and store
			inet_ntop(AF_INET6, &(ip6_header->ip6_src), src_ip6, INET6_ADDRSTRLEN);
			inet_ntop(AF_INET6, &(ip6_header->ip6_dst), dst_ip6, INET6_ADDRSTRLEN);

			// Check the protocol TPC/UDP
			switch(ip6_header->ip6_nxt){		// Line 45 in ip6.h
				
				case IPPROTO_TCP:
					printf("\tPacket Number: %d\n", total_packets);				
					printf(" [->] IP Version: 	IPv6\n");
					printf(" [->] Source IP: 	%s\n", src_ip6);
					printf(" [->] Destination IP: 	%s\n", dst_ip6);

					// Get the ports
					int tcp_src_port;
					int tcp_dst_port;

					// Now constuct the tcp_header
					struct tcphdr *tcp_header = (struct tcphdr *)(pkt_data + frame_size);

					tcp_src_port= ntohs(tcp_header->th_sport);
					tcp_dst_port = ntohs(tcp_header->th_dport);

					printf(" [->] Source Port: 	 %d\n", tcp_src_port);
					printf(" [->] Destination Port:  %d\n", tcp_dst_port);

					// Increase frame size by the data amount to calc payload
					frame_size += sizeof(struct tcphdr);
					
					int tcp_payload = pkt_header->len - frame_size; //data remains

					printf(" [->] Protocol: 	 TCP\n");
					printf(" [->] Header Length:     %d\n", (int)sizeof(struct tcphdr));
					printf(" [->] Payload:		 %d\n\n", tcp_payload);

					// Here create a new net flow
		



					total_bytes_tcp += tcp_payload + frame_size; // total payload or all total packet???
					total_tcp_packets++;	
					break;

				case IPPROTO_UDP:
					printf("\tPacket Number: %d\n", total_packets);				
					printf(" [->] IP Version: 	 IPv6\n");
					printf(" [->] Source IP:  	 %s\n", src_ip6);
					printf(" [->] Destination IP: 	 %s\n", dst_ip6);
				
					// Get the ports
					int udp_src_port;
					int udp_dst_port;

					// Now constuct the tcp_header
					struct udphdr *udp_header = (struct udphdr *)(pkt_data + frame_size);

					udp_src_port= ntohs(udp_header->uh_sport);
					udp_dst_port = ntohs(udp_header->uh_dport);

					printf(" [->] Source Port: 	 %d\n", udp_src_port);
					printf(" [->] Destination Port:  %d\n", udp_dst_port);

					// Increase frame size by the data amount to calc payload
					frame_size += sizeof(struct udphdr);
					
					int udp_payload = pkt_header->len - frame_size;

					printf(" [->] Protocol: 	 UDP\n");
					printf(" [->] Header Length:     %d\n", (int)sizeof(struct udphdr));
					printf(" [->] Payload:		 %d\n\n", udp_payload);




					total_bytes_udp += udp_payload + frame_size; // total payload or all total packet???
					total_udp_packets++;
					// exit(-1); -> to stop at an IPv6 packet
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

	return;
}


/// @brief This function will start capturing traffic from a network interface
void online_monitor(char *interface){

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
		  );
	
    exit(-1);
}

int main(int argc, char *argv[])
{
    int ch;
    while((ch = getopt(argc, argv, "hr:i:f:")) != -1) {
	    switch(ch) {		
		    case 'i':
				
			    break;
		    case 'r': 
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