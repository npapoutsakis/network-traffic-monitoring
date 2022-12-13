#include <stdio.h>
#include <stdlib.h>

















void usage(void){
    printf(
	       "\n"
	       "Usage:\n\n"
		   "Options:\n"
		   "-i Network interface name \n"
		   "-r Packet capture file name\n"
           "-f Filter expression\n"
		   "-h Help message\n\n"
		  );
    
    exit(-1);
}

int main()
{

    //add code here
    usage();

    return 0;
}