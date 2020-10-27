#include <stdio.h>
#include <stdlib.h>

#include <pcap.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <math.h>

//ethernet headers 14 bytes & address 6 bytes
#define SIZE_ETHERNET 14
#define ETHER_ADDR_LEN 6

/*structure of ethernet, IP, TCP, UDP, DNS headers*/
//ethernet header struct
struct sniff_ethernet{
	u_char ether_dhost[ETHER_ADDR_LEN];
	u_char ether_shost[ETHER_ADDR_LEN];
	u_short ether_type;
};
//IP header struct
struct sniff_ip{
	u_char ip_vh1;  				//version << 4 | header length >> 2
	u_char ip_tos; 	 				//type of service
	u_short ip_len;	 				//total length
	u_short ip_id;					//identification
	u_short ip_off;					//fragment offset field
	#define IP_RF 0x8000			//reserved fragment flag
	#define IP_DF 0x4000			//dont fragment flag
	#define IP_MF 0x2000			//more fragments flag
	#define IP_FOOMASK 0x1fff		//mask for fragmenting bits
	u_char ip_tt1;					//time to live
	u_char ip_p;					//protocal
	u_short ip_sum;					//checksum
	struct in_addr ip_src,ip_dst;	//source and destination address
};
#define IP_HL(ip)	(((ip)->ip_vh1)&0x0f)
#define IP_v(ip)	(((ip)->ip_vh1)>>4)
//TCP header sturct
typedef u_int tcp_seq;
struct sniff_tcp {
		u_short th_sport;	// source port
		u_short th_dport;	// destination port 
		tcp_seq th_seq;		// sequence number 
		tcp_seq th_ack;		// acknowledgement number 
		u_char th_offx2;	// data offset, rsvd 
	#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
		u_char th_flags;
	#define TH_FIN 0x01
	#define TH_SYN 0x02
	#define TH_RST 0x04
	#define TH_PUSH 0x08
	#define TH_ACK 0x10
	#define TH_URG 0x20
	#define TH_ECE 0x40
	#define TH_CWR 0x80
	#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
		u_short th_win;		// window 
		u_short th_sum;		// checksum 
		u_short th_urp;		// urgent pointer 
};
//UDP header struct
struct sniff_udp {
     u_int16_t uh_sport;	//source port
     u_int16_t uh_dport;	//destination port
     u_int16_t uh_ulen;		//udp length
     u_int16_t uh_sum;
    };
//DNS header struct
struct sniff_dns {
	u_int16_t id;
	u_int16_t flags;
	u_int16_t QDCOUNT;
	u_int16_t ANCOUNT;
	u_int16_t NSCOUNT;
	u_int16_t ARCOUNT;
};


//check what kind of header captured 0: requests 1:response -1:else
int re_type(const u_char *payload, int len){
	//RESPONSE
	if(strncmp((char*)payload,"HTTP",4)==0)
		return 1;
	//REQUEST
	const u_char *ch;
	int space_count = 0;
	ch=payload;
	for (int i = 0; i < len; i++) {
		//process the first line
		if (strncmp((char*)ch, "\r\n", 2) == 0 || !isprint(*ch)) {
			break;
		}
		if (isspace(*ch)) {
			space_count++;
		}
		if (space_count == 2 && strncmp((char*)ch, " HTTP", 5) == 0) {
			return 0;
		}
		ch++;
	}
	//if cannot get RESPONSE or REQUEST
	return -1;
}

//print out the HTTP headers of the captured packet
void print_payload(const u_char *payload, int len, int header_num){
	int end_header=0;
	int is_post=0;
	const u_char *ch;

	if(strncmp((char*)payload,"POST",4)==0){
		is_post=1;
	}
	ch=payload;
	for(int i=0;i<len;i++){
		if(end_header&&is_post){
			if(isprint(*ch)||isspace(*ch))
				printf("%c",*ch);
		}
		else{
			if(isprint(*ch)||isspace(*ch)){
				printf("%c",*ch);
			}
			else{
				printf(".");
			}
			if(strncmp((char*)ch,"\r\n\r\n",4)==0){
				end_header=1;
				printf("\n\r\n");
				if(!is_post)
					break;
				//skip to request
				ch=ch+3;
				i=i+3;
			}
		}
		ch++;
	}

	//terminate and print a new line
	if(!end_header){
		printf("\r\n\r\n");
	}
	printf("\n");
	return;
}
//HTTP packet getter
/*
	This is the main HTTP packet getter to check the size of payload
	If payload exist, it will determine the header type REQUEST or RESPONSE
	The screen print will be called the above function: print_payload()
*/
void get_packet_http(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
	static int count=1;						//count header
	const struct sniff_ethernet *ethernet;	//ethernet header
	const struct sniff_ip *ip;				//IP header
	const struct sniff_tcp *tcp;			//TCP header
	const u_char *payload;					//Packet payload
	int ip_size;
	int tcp_size;
	int payload_size;

	ethernet=(struct sniff_ethernet*)(packet);
	ip=(struct sniff_ip*)(packet + SIZE_ETHERNET);
	ip_size=IP_HL(ip)*4;
	if(ip_size<20){
		printf("Invalid IP header length: %u bytes\n",ip_size);
		return;
	}
	tcp=(struct sniff_tcp*)(packet+SIZE_ETHERNET+ip_size);
	tcp_size=TH_OFF(tcp)*4;
	if(tcp_size<20){
		printf("Invalid TCP header length: %u bytes\n",tcp_size);
		return;
	}

	//get TCP segement size
	payload = (u_char *)(packet+SIZE_ETHERNET+ip_size+tcp_size);
	payload_size=ntohs(ip->ip_len) - (ip_size+tcp_size);
	
	if(payload_size>0){
		int p_type=re_type(payload,payload_size);
		if (p_type == -1)
		{	
			return;
		}

		printf("%d",count);

		//print ip
		printf(" %s:",inet_ntoa(ip->ip_src));
		//source port
		printf("%d ",ntohs(tcp->th_sport));

		//destination ip
		printf("%s:",inet_ntoa(ip->ip_dst));
		//destination port
		printf("%d HTTP: ",ntohs(tcp->th_dport));

		//print the header type
		if(p_type==0){
                        printf("Request\r\n");
                }
                else{
                        printf("Response\r\n");
                }

		//print caputred header info
		print_payload(payload,payload_size,count);
		count++;
	}
	return;
}


//DNS packet getter
/*
	This is the main DNS packet getter to check the size of payload
	If payload exist, it will check the is port 53 or not
	Unlike the above HTTP packet getter this function contanis the print part
*/
void get_packet_dns(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
        int i;
        static int count =1;
        const u_char *ch;						//Packet payload 
        
        const struct sniff_ethernet *ethernet;	//ethernet header
        const struct sniff_ip *ip;				//IP header
        const struct sniff_udp *udp;			//UDP header
        const char *payload;					//Packet payload
        int ip_size;
        int udp_size;
        int payload_size;
       
        ethernet = (struct sniff_ethernet*)(packet);
        ip=(struct sniff_ip*)(packet+SIZE_ETHERNET);
        ip_size=IP_HL(ip)*4;
        if(ip_size<20){
		printf("Invalid IP header length: %u bytes\n",ip_size);
		return;
		}
	
		udp=(struct sniff_udp*)(packet+SIZE_ETHERNET+ip_size);
		udp_size=ntohs(udp->uh_ulen);
		//get UDP segement size
		payload=(u_char*)(packet+SIZE_ETHERNET+ip_size+8);
		payload_size=ntohs(ip->ip_len)-(ip_size+8);
	
		if(payload_size>0){
			//DNS using port 53
			if (ntohs(udp->uh_dport) == 53 || ntohs(udp->uh_sport) == 53) {
				ch = payload;
				printf("%d",count);

				//print ip
				printf(" %s:",inet_ntoa(ip->ip_src));
				//source port
				printf("%d ",ntohs(udp->uh_sport));

				//destination ip
				printf("%s:",inet_ntoa(ip->ip_dst));
				//destination port
				printf("%d DNS ID: ",ntohs(udp->uh_dport));

			
				struct sniff_dns *dns_protocol;
				dns_protocol=(struct sniff_dns *)(packet+SIZE_ETHERNET+ip_size+8);
				printf("%04x\n",ntohs(dns_protocol->id));

				//because the flag is a hex num -> change the hex to binary
				char hex[5];
				char binary[16]={0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
				sprintf(hex,"%04x",ntohs(dns_protocol->flags));
				int i,j=0;
				int length=0;
				int decimal=0;
				for(length=0;hex[length]!='\0';++length);
				for(i=0;hex[i]!='\0';++i,--length){
				if(hex[i]>='0'&&hex[i]<='9') decimal+=(hex[i]-'0')*pow(16,length-1);
				if(hex[i]>='A'&&hex[i]<='F') decimal+=(hex[i]-55)*pow(16,length-1);
				if(hex[i]>='a'&&hex[i]<='f') decimal+=(hex[i]-87)*pow(16,length-1);
				}
				while(decimal!=0){
				binary[j++]=decimal%2;
				decimal=decimal/2;
				}
				//changed done
   
				//print DNS header info
				printf("%d | ",binary[15]);//QR
				printf("%d%d%d%d | ",binary[14],binary[13],binary[12],binary[11]);//OP CODE
				printf("%d | ",binary[10]);//AA
				printf("%d | ",binary[9]);//TC
				printf("%d | ",binary[8]);//RD
				printf("%d | ",binary[7]);//RA
				printf("%d%d%d | ",binary[6],binary[5],binary[4]);//Z
				printf("%d%d%d%d",binary[3],binary[2],binary[1],binary[0]);//R CODE
				printf("\n");
				printf("QDCOUNT:%d\n",ntohs(dns_protocol->QDCOUNT));
				printf("ANCOUNT:%d\n",ntohs(dns_protocol->ANCOUNT));
				printf("NSCOUNT:%d\n",ntohs(dns_protocol->NSCOUNT));
				printf("ARCOUNT:%d\n",ntohs(dns_protocol->ARCOUNT));
	
				printf("\n");
			}
		count++;
		}
}
        


// main function
int main(int args, char **argv){
	char *device = NULL;				//name of captured device
	pcap_t *capd;						//capture device

	pcap_if_t *alldevs;					//get all devices
	pcap_if_t *d;

	bpf_u_int32 netp;					//ip
	bpf_u_int32 maskp;					//subnet mask

	int ret=1;							//store pcap_findalldevs() return value
										// 0: success  -1: fail
	int device_num=1;					//default the device selected number
	int sniffer_type=1;					// 1: HTTP 2: DNS
	struct in_addr addr;				//address
	char *net;

	int num_packets=-1;					//number of packets
	char errbuf[PCAP_ERRBUF_SIZE];		//error message buffer to store messages
	struct bpf_program filter_program;	//compiled filter program

	//find all devices
	ret = pcap_findalldevs(&alldevs,errbuf);
	if(ret == -1){
		printf("pcap_findalldevs error!\n");
		return -1;
	}

	//print interface screen
	printf("================= Devices List =================\n");
	for(d=alldevs;d;d=d->next){
		printf("%d. %s",device_num++,d->name);

		if(d->description) printf(" (%s)\n",d->description);
		else printf("(None)\n");
	}

	//get input from user
	printf("Enter the device number (1-%d) >> ",device_num-1);
	scanf("%d",&device_num);
	printf("Which header do you want to sniff? (1:HTTP 2:DNS) >> ");
	scanf("%d",&sniffer_type);
	printf("\n");

	device_num--;

	//default device
	for(d=alldevs;device_num>0;d=d->next,device_num--);

	ret=pcap_lookupnet(d->name,&netp,&maskp,errbuf);

	//HTTP header sniffer
	if (sniffer_type == 1)
	{
		char filter_exp[] = "tcp port 80"; //filter expression[3]
		if (ret == -1) {
			printf("pcap_lookupnet Error! error message: %s\n", errbuf);
			pcap_freealldevs(alldevs);
			netp = 0;
			maskp = 0;
			return -1;
		}

		//pcap library default call funtion
		//open caputre device
		capd = pcap_open_live(d->name, BUFSIZ, 1, 1000, errbuf);
		if (capd == NULL) {
			fprintf(stderr, "Couldn't open device %s: %s\n", d->name, errbuf);
			return(2);
		}
		//compile the filter expression
		if (pcap_compile(capd, &filter_program, filter_exp, 0, netp) == -1) {
			fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(capd));
			return(2);
		}
		//apply compiled filter
		if (pcap_setfilter(capd, &filter_program) == -1) {
			fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(capd));
			return(2);
		}

		//callback function (HTTP sniffer)
		pcap_loop(capd, num_packets, get_packet_http, NULL);

		//clear
		pcap_freecode(&filter_program);
		pcap_close(capd);
		printf("\nCapture complete!\n");
	}
	
	//DNS header sniffer
	if(sniffer_type==2){
		char filter_exp[] = "udp port 53"; // filter expression[3]
	    //open caputre device
        capd = pcap_open_live(d->name,BUFSIZ,1,1000,errbuf);
        if(capd==NULL){
                fprintf(stderr,"Couldn't open device %s: %s\n",d->name,errbuf);
               	return(2);
        }

		//pcap library default call funtion
        //compile the filter expression
        if(pcap_compile(capd,&filter_program,filter_exp,0,netp)==-1){
                fprintf(stderr,"Couldn't parse filter %s: %s\n",filter_exp,pcap_geterr(capd));
                return(2);
        }
        //apply compiled filter
        if(pcap_setfilter(capd,&filter_program)==-1){
                fprintf(stderr, "Couldn't install filter %s: %s\n",filter_exp,pcap_geterr(capd));
                return(2);
        }
		//callback function (DNS sniffer)
	    pcap_loop(capd, num_packets, get_packet_dns,NULL);

		//clear
		pcap_freecode(&filter_program);
		pcap_close(capd);
		printf("\nCapture complete!\n");
	}
	return 0;
}
