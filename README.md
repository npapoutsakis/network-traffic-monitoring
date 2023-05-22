# network-traffic-monitoring

 
In this assignment we implemented a network traffic monitoring tool using the Packet 
Capture Library in C. For more information about the library we visited the following
sites: 
        1. https://linux.die.net/man/3/pcap
        2. https://www.tcpdump.org

We were expected to capture packets from live network and from a .pcap file and extract 
all information about TCP and UDP packets.

For the live capture, online_monitor() is used, sets a store_flag to 1 and calls the
callback function of pcap_loop() in order to extract the information.

For the file capture, offline_monitor() is used. Using pcap_loop we could easily extract all
information.

To successfully get the info, netinet library is used which contains all structs about the 
ethernet frame.

The function packet_handler() is called everytime a packet was detected and extracts all info such as:
    1. IP version
    2. Source/Destination port
    3. Source/Destination IP
    4. Protocol TCP/UDP

As for the retransmissions, we cannot tell if a UDP packet is retransmitted at the transport layer.
It's a connectionless protocol so, UDP retransmissions are handled in application layer. On the other
hand, TCP retransmissions can be found and to do that, we created a simple linked list of TCP network
flows and check wether the a retransmission occurs.

As for the filter mechanism, we couldn't use pcap_compile() and pcap_setfilter() so we added some 
extra if statement logic to the packet_handler() and got our result.

To achieve that, checkSubstring() is used to check if a substring contains a specific string and 
parseFilter() to parse the data available given from user.

The filter expressions that can be used are:
        1. "ip version "
        2. "port "
        3. "ip "
        4. "protocol "
        5. "src port "
        6. "dst port "
        7. "src ip "
        8. "dst ip "


Makefile
    Use command 'make' to complile the files
    Use command 'make clean' to delete all executables
    **make sure you have installed libpcap-dev in your system**

Examples to execute:
    For file capture:
        1. ./pcap_ex -r <filename>
    
    For live capture:
        1. sudo ./pcap_ex -i eth0 (or enp0s3 for vms)
        2. sudo ./pcap_ex -i eth0 -f "src port 53"

