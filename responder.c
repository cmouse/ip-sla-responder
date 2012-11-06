#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <net/ethernet.h> /* the L2 protocols */
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <pcap/pcap.h>
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>
#include <netpacket/packet.h>
#include <time.h>

#define PCAP_FILTER_OWN_AND_ICMP_OR_UDP "ether dst d0:d0:fd:09:34:2c and (udp or icmp)" 

#define ETH_O_DEST 0
#define ETH_O_SOURCE 6
#define ETH_O_PROTO 12

#define RESP_ETH_HEADER(x) ((const struct ethhdr*)(x))

#define IP_MAGIC 45

#define IP_START ETH_HLEN+4
#define RESP_IP_HEADER(x) ((const struct iphdr*)(x+IP_START))

#define IP_O_TOS IP_START+1
#define IP_O_TOT_LEN IP_START+2
#define IP_O_ID IP_START+4
#define IP_O_FRAG_OFF IP_START+6
#define IP_O_TTL IP_START+8
#define IP_O_PROTO IP_START+9
#define IP_O_CHKSUM IP_START+10
#define IP_O_SADDR IP_START+12
#define IP_O_DADDR IP_START+16

#define ICMP_START IP_START+20

struct timespec res0;

void bin2hex(const unsigned char *data, size_t dlen) {
   size_t i;
   printf("%08x ", 0);
   for(i=0; i < dlen; i++) {

     if ((i % 8) == 0 && i > 0)
      printf("\n%08x ", (unsigned int)i);
     printf("%02x ", data[i]);
   }
   printf("\n");
}

inline uint16_t ip_checksum(const void *vdata, size_t dlen, uint16_t *target) {
   register uint16_t word16;
   register uint32_t sum=0;
   register size_t i;
   unsigned char *buff = (unsigned char *)vdata;

   // make 16 bit words out of every two adjacent 8 bit words in the packet
   // and add them up
   for (i=0;i<dlen-1;i=i+2){
     word16 =((buff[i]<<8)&0xff00)+(buff[i+1]&0xff);
     sum += (uint32_t) word16;	
   }
   if (i != dlen) sum += buff[dlen-1]&0xff;

   // take only 16 bits out of the 32 bit sum and add up the carries
   sum = (sum & 0xffff)+(sum >> 16);
   sum += (sum >> 16);

   // one's complement the result
   sum = ~sum;
   
   (*target) = htons(((uint16_t)sum));
   return *target;
}

void process_and_send_icmp(int fd, u_char *bytes, size_t plen) {
   uint32_t tmp;
   char etmp[ETH_ALEN];
   struct timespec res;

   memcpy(etmp, bytes, ETH_ALEN);
   memmove(bytes, bytes+ETH_ALEN, ETH_ALEN);
   memcpy(bytes+ETH_ALEN, etmp, ETH_ALEN);

   // swap ip src/dst
   tmp = *(uint32_t*)(bytes+IP_O_SADDR);
   *(uint32_t*)(bytes+IP_O_SADDR) = *(uint32_t*)(bytes+IP_O_DADDR);
   *(uint32_t*)(bytes+IP_O_DADDR) = tmp;

   // that's the IP part, recalculate checksum
   *(uint16_t*)(bytes+IP_O_CHKSUM)=0;
   ip_checksum(bytes+IP_START, 20, (uint16_t*)(bytes+IP_O_CHKSUM));

   // fix icmp header
   *(uint32_t*)(bytes+ICMP_START) = 0;
   // recalculate checksum
   ip_checksum(bytes+ICMP_START, plen - ETH_HLEN - 4 - 20, (uint16_t*)(bytes+ICMP_START+2));
   // send packet
   send(fd, bytes, plen, 0);
   clock_gettime(CLOCK_REALTIME, &res);
   printf("%lu s %lu ns\n", res.tv_sec - res0.tv_sec, res.tv_nsec - res0.tv_nsec);   
}

void pak_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes)
{
   u_char response[1500];
   int fd;
   size_t plen;
   clock_gettime(CLOCK_REALTIME, &res0);

   fd = *(int*)user;
   // expect vlan

   if (*(unsigned short*)(bytes+ETH_O_PROTO) != htons(ETH_P_8021Q)) return;   

   plen = ntohs(*(unsigned short*)(bytes+IP_O_TOT_LEN))+ETH_HLEN+4; // total size of entire packet

   if (plen > 1500) return; // sorry, we are bit silly

   // determine ip packet size
   memcpy(response,bytes,plen);

   if (bytes[IP_O_PROTO] == 1) {
     // it's icmp.
     process_and_send_icmp(fd,response,plen);
   }
}

void bpf_program(pcap_t *p, struct bpf_program *fp)
{
  char errbuf[PCAP_ERRBUF_SIZE];
  if (pcap_compile(p, fp, PCAP_FILTER_OWN_AND_ICMP_OR_UDP, 1, PCAP_NETMASK_UNKNOWN) != 0) {
    pcap_perror(p, "pcap_compile");
    exit(1);
  } 
}

int main(void) {
   int fd;
   struct ifreq ifr;
   struct sockaddr_ll sa;
   struct bpf_program fp;
   int val = 4;
   pcap_t *p;
   char errbuf[PCAP_ERRBUF_SIZE];
   fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
   memset(&ifr,0,sizeof ifr);
   sprintf(ifr.ifr_name, "eth0");
   ioctl(fd, SIOCGIFINDEX, &ifr);
   memset(&sa,0,sizeof sa);
   sa.sll_family = AF_PACKET;
   sa.sll_ifindex = ifr.ifr_ifindex;
   sa.sll_protocol = htons(ETH_P_ALL);
   bind(fd, (struct sockaddr*)&sa, sizeof sa);
   p = pcap_create("eth0", errbuf);
   pcap_activate(p);
   if (pcap_set_datalink(p, 1) != 0) {
     pcap_perror(p, "pcap_set_datalink");
     exit(1);
   }
   bpf_program(p, &fp);
   if (pcap_setfilter(p, &fp)!=0) {
     pcap_perror(p, "pcap_setfilter");
     exit(1);
   }
   pcap_set_snaplen(p, 65535);
   pcap_loop(p, 0, pak_handler, (u_char*)&fd);
   pcap_close(p);

   return 0;
}
