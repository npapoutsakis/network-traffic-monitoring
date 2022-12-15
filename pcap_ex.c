#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pcap.h>

#include <netinet/ether.h>
#include <netinet/ip.h>
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
};




/// @brief Print the statistics, aka global counters 
void statistics(void){
	printf("+----------------------------------------------+\n");
	printf("|                  Statistics                  |\n");
	printf("+----------------------------------------------+\n");
	printf("  [+] Total network flows captured: %d\n", total_network_flows);
	printf("  [+] Total TCP network flows captured: %d\n", tcp_network_flows);
	printf("  [+] Total UDP network flows captured: %d\n", udp_network_flows);
	printf("  [+] Total packets captured: %d\n", total_packets);
	printf("  [+] Total TCP packets captured: %d\n", total_tcp_packets);
	printf("  [+] Total UDP packets captured: %d\n", total_udp_packets);
	printf("  [+] Total bytes of TCP packets captured: %d\n", total_bytes_tcp);
	printf("  [+] Total bytes of UDP packets captured: %d\n", total_bytes_udp);
	return;
}



void extractTCP(const u_char *pkt_data, int size){



	return;
}


void extractUDP(const u_char *pkt_data, int size){



	return;
}


/// @brief Callback function invoked by libpcap for every incoming packet
void packet_handler(u_char *user, const struct pcap_pkthdr *pkt_header, const u_char *pkt_data){

	// Increase total number of packets
	total_packets++;
	
	// Here will see what the packet contains
	// Useful information: https://www.winpcap.org/docs/docs_40_2/html/group__wpcap__tut6.html
	struct iphdr *ip_header = (struct iphdr *)(pkt_data + sizeof(struct ethhdr));
	
	if(ip_header == NULL)	
		exit(EXIT_FAILURE);

	// struct ethhdr *eth_header = (struct ethhdr *)(pkt_data);
	// printf("%d\n", ip_header->protocol);

	switch(ip_header->protocol){
		//17
		case IPPROTO_UDP:
			total_udp_packets++;
			extractUDP(pkt_data, pkt_header->len);
			break;
		//6
		case IPPROTO_TCP:
			total_tcp_packets++;
			extractTCP(pkt_data, pkt_header->len);
			break;
		default:
			// Skipped!
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
				online_monitor(optarg);
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