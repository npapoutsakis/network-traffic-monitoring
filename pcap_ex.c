#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pcap.h>

#include <netinet/ether.h>
#include <netinet/ip.h>


// Declaring global counters
int total_packets = 0;

int total_udp_packets = 0;
int total_tcp_packets = 0;
int total_network_flows = 0;

int tcp_network_flows = 0;
int udp_network_flows = 0;

int total_bytes_tcp = 0;
int total_bytes_udp = 0;



typedef struct networkFlow {



		

} networkFlow;


/// @brief Callback function invoked by libpcap for every incoming packet
void packet_handler(u_char *user, const struct pcap_pkthdr *pkt_header, const u_char *pkt_data){
	
	// Here will see what the packet contains
	// Useful information: https://www.winpcap.org/docs/docs_40_2/html/group__wpcap__tut6.html
	struct iphdr *ih = NULL;
	
	ih = (struct iphdr *)(pkt_data + sizeof(struct ethhdr));

	switch(ih->protocol){
		//17
		case IPPROTO_UDP:
			total_udp_packets++;
			break;
		//6
		case IPPROTO_TCP:
			total_tcp_packets++;
			break;

		default:
			// Skipped!
			break;
	}

	total_packets++;

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
	pcap_loop(read_packets, 0, &packet_handler, NULL);

	// Close the opened file
	pcap_close(read_packets);

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