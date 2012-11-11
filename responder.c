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

#define PCAP_FILTER_OWN_AND_ICMP_OR_UDP "arp or (dst host %s and (udp or icmp))"

#define ETH_O_DEST 0
#define ETH_O_SOURCE 6
#define ETH_O_PROTO 12

#define IP_MAGIC 45

#define IP_START ETH_HLEN+4
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
#define ICMP_DATA ICMP_START+8

#define UDP_START IP_START+20
#define UDP_SPORT UDP_START
#define UDP_DPORT UDP_START+2
#define UDP_LEN UDP_START+4
#define UDP_CHECKSUM UDP_START+6
#define UDP_DATA UDP_START+8

#define ARP_START ETH_HLEN+4

struct timespec res0;
static uint32_t dest_ip;
static u_char dest_mac[ETH_ALEN];

uint32_t get_ts_utc(struct timespec *res) {
   struct tm tm;
   clock_gettime(CLOCK_REALTIME,res);
   gmtime_r(&res->tv_sec, &tm);
   return (tm.tm_hour*3600+tm.tm_min*60+tm.tm_sec)*1000 + (res->tv_nsec/1000);
}

void bin2hex(const unsigned char *data, size_t dlen) {
   size_t i;
   for(i=0; i < dlen; i++) {
     if ((i % 16) == 0 || i == 0)
      printf("\n%04x  ", (unsigned int)i);
     printf("%02x ", data[i]);
   }
   printf("\n");
}

inline uint16_t ip_checksum(const void *vdata, size_t dlen, uint16_t *target) {
   register uint16_t word16;
   register uint32_t sum=0;
   register size_t i;
   const unsigned char *buff = (const unsigned char *)vdata;

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

inline uint16_t tcp_checksum(const u_char *src_addr, const u_char *dest_addr, u_char *buff, size_t dlen, uint16_t *target) {
   register uint16_t word16;
   register uint32_t sum=0;
   register size_t i;
   uint16_t pad;
   if ((dlen&1)==1) {
      pad=1;
      buff[dlen]=0;
   }
   for (i=0;i<dlen+pad;i=i+2){
     word16 =((buff[i]<<8)&0xff00)+(buff[i+1]&0xff);
     sum += (uint32_t)word16;
   }
   for (i=0;i<4;i=i+2){
     word16 =((src_addr[i]<<8)&0xFF00)+(src_addr[i+1]&0xFF);
     sum=sum+word16;
   }
   for (i=0;i<4;i=i+2){
     word16 =((dest_addr[i]<<8)&0xFF00)+(dest_addr[i+1]&0xFF);
     sum=sum+word16; 
   }
   sum = sum + 17 + dlen;
   sum = (sum & 0xffff)+(sum >> 16);
   sum += (sum >> 16);
   sum = ~sum;
   (*target) = htons(((uint16_t)sum));
   return *target;
}

inline void swapmac(u_char *bytes) {
   u_char etmp[ETH_ALEN];
   memcpy(etmp, bytes, ETH_ALEN);
   memmove(bytes, bytes+ETH_ALEN, ETH_ALEN);
   memcpy(bytes+ETH_ALEN, etmp, ETH_ALEN);
}

inline void swapip(u_char *bytes) {
   uint32_t tmp;
   tmp = *(uint32_t*)(bytes+IP_O_SADDR);
   *(uint32_t*)(bytes+IP_O_SADDR) = *(uint32_t*)(bytes+IP_O_DADDR);
   *(uint32_t*)(bytes+IP_O_DADDR) = tmp;
} 

void process_and_send_arp(int fd, u_char *bytes, size_t plen) {
/*
0000  d0 d0 fd 09 34 2c 88 43 e1 de 22 c0 81 00 c0 c9   ....4,.C..".....
0010  08 06 00 01 08 00 06 04 00 01 88 43 e1 de 22 c0   ...........C..".
0020  3e ec 84 9e d0 d0 fd 09 34 2c 3e ec 84 9f 00 00   >.......4,>.....
0030  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
Address Resolution Protocol (request)
    Hardware type: Ethernet (1)
    Protocol type: IP (0x0800)
    Hardware size: 6
    Protocol size: 4
    Opcode: request (1)
    [Is gratuitous: False]
    Sender MAC address: 88:43:e1:de:22:c0 (88:43:e1:de:22:c0)
    Sender IP address: 62.236.132.158 (62.236.132.158)
    Target MAC address: d0:d0:fd:09:34:2c (d0:d0:fd:09:34:2c)
    Target IP address: 62.236.132.159 (62.236.132.159)
Address Resolution Protocol (reply)
    Hardware type: Ethernet (1)
    Protocol type: IP (0x0800)
    Hardware size: 6
    Protocol size: 4
    Opcode: reply (2)
    [Is gratuitous: False]
    Sender MAC address: d0:d0:fd:09:34:2c (d0:d0:fd:09:34:2c)
    Sender IP address: 62.236.132.159 (62.236.132.159)
    Target MAC address: 88:43:e1:de:22:c0 (88:43:e1:de:22:c0)
    Target IP address: 62.236.132.158 (62.236.132.158)

0000 ff ff ff ff ff ff 88 43 e1 de 22 c0 81 00 c0 cb
0010 08 06 00 01 08 00 06 04 00 01 88 43 e1 de 22 c0
0020 3e ec ff b3 00 00 00 00 00 00 3e ec ff b2 00 00
0030 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00

0000 88 43 e1 de 22 c0 d0 d0 fd 09 34 2c 81 00 c0 cb
0010 08 06 00 01 08 00 06 04 00 02 d0 d0 fd 09 34 2c
0020 3e ec ff b2 00 00 00 00 00 00 3e ec ff b2 00 00
0030 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00

*/
    u_char tmp[ETH_ALEN];
    struct msghdr msg;
    struct iovec iovec;

    if (*(uint16_t*)(bytes+ARP_START)!=0x0100 ||
        *(uint16_t*)(bytes+ARP_START+2)!=0x008 ||
        *(uint8_t*)(bytes+ARP_START+4)!=0x06 ||
        *(uint8_t*)(bytes+ARP_START+7)!=0x01 ||
        *(uint32_t*)(bytes+ARP_START+24)!=dest_ip) {
      return; // ignore
    }

    // move sender to target
    memmove(bytes, bytes+ETH_ALEN, ETH_ALEN);
    // in case it's broadcast
    memcpy(bytes+ETH_ALEN, dest_mac, ETH_ALEN);
    // move sender to target, again
    memmove(bytes+ARP_START+18, bytes+ARP_START+8, 10);
    // fill in sender
    memcpy(bytes+ARP_START+8, dest_mac, ETH_ALEN);
    memcpy(bytes+ARP_START+8+ETH_ALEN, &dest_ip, 4);
    bytes[ARP_START+7] = 0x02;

    // clean up response
    memset(bytes+46,0,0x40);

    // we use msghdr here.
    msg.msg_name = NULL;
    msg.msg_namelen = 0;
    iovec.iov_base = bytes;
    iovec.iov_len = 0x40;
    msg.msg_iov = &iovec;
    msg.msg_iovlen = 1;
    msg.msg_control = NULL;
    msg.msg_controllen = 0;
    msg.msg_flags = 0;

    if (sendmsg(fd, &msg, 0) < 0x40) 
      perror("send_arp");
}


void process_and_send_udp(int fd, u_char *bytes, size_t plen) {
   uint32_t recv;
   struct timespec res;
   
   recv = get_ts_utc(&res);
   swapmac(bytes);
   swapip(bytes);

   // that's the IP part, recalculate checksum
   *(uint16_t*)(bytes+IP_O_CHKSUM)=0;
   ip_checksum(bytes+IP_START, 20, (uint16_t*)(bytes+IP_O_CHKSUM));

   if (*(uint16_t*)(bytes+UDP_DPORT) == ntohs(7)) {
      // just send it back with swapped ports
      uint16_t tmp = *(uint16_t*)(bytes+UDP_DPORT);
      *(uint16_t*)(bytes+UDP_DPORT) = *(uint16_t*)(bytes+UDP_SPORT);
      *(uint16_t*)(bytes+UDP_SPORT) = tmp;
      // wonder if this is RPM
      if (*(uint16_t*)(bytes+UDP_DATA+28) == 0x0100 &&
       *(uint16_t*)(bytes+UDP_DATA+30) == 0x1096 && plen > 90) {
         // this is a juniper RPM format. we need to put here the recv/trans stamp too
         uint32_t usec;
         memcpy(bytes+UDP_START+12, &recv, 4);
         memcpy(bytes+UDP_START+16, &recv, 4);
         memcpy(bytes+UDP_START+0x1c, "\xee\xdd\xcc\xbb\xaa\xcc\xdd\xee", 8);
         clock_gettime(CLOCK_MONOTONIC, &res); // juniper uses silly epoch, so can I
         usec = htonl(res.tv_nsec/1000);
         res.tv_sec = htonl(res.tv_sec);
         memcpy(bytes+UDP_START+0x2c, &res.tv_sec, 4);
         memcpy(bytes+UDP_START+0x30, &usec, 4);
      }
   } else {
      return; // do not process
   }

   *(uint16_t*)(bytes+UDP_CHECKSUM) = 0;
   tcp_checksum(bytes+IP_O_SADDR, bytes+IP_O_DADDR, bytes+UDP_START, ntohs(*(uint16_t*)(bytes+UDP_LEN)), (uint16_t*)(bytes+UDP_CHECKSUM));
   // as per spec
   if (*(uint16_t*)(bytes+UDP_CHECKSUM) == 0) 
     *(uint16_t*)(bytes+UDP_CHECKSUM) = 0xffff;
   send(fd, bytes, plen, 0);
}

void process_and_send_icmp(int fd, u_char *bytes, size_t plen) {
   uint32_t tmp,recv;
   struct timespec res;
   
   recv = get_ts_utc(&res0);

   swapmac(bytes);
   swapip(bytes);

   // that's the IP part, recalculate checksum
   *(uint16_t*)(bytes+IP_O_CHKSUM)=0;
   ip_checksum(bytes+IP_START, 20, (uint16_t*)(bytes+IP_O_CHKSUM));

   // check for ICMP type
   if (*(uint16_t*)(bytes+ICMP_START) == 8) { // icmp echo
     // this is simple ping, change it to response.
     *(uint32_t*)(bytes+ICMP_START) = 0;
   } else if (*(uint16_t*)(bytes+ICMP_START) == 0x000d && plen > 90 &&
       *(uint16_t*)(bytes+ICMP_DATA+28) == 0x0100 &&
       *(uint16_t*)(bytes+ICMP_DATA+30) == 0x1096) {
      // this is a juniper RPM format. we need to put here the recv/trans stamp too
      uint32_t usec,sent;
      memcpy(bytes+ICMP_START+12, &recv, 4);
      clock_gettime(CLOCK_MONOTONIC, &res); // juniper uses silly epoch, so can I
      usec = htonl(res.tv_nsec/1000);
      res.tv_sec = htonl(res.tv_sec);
      memcpy(bytes+ICMP_START+0x2c, &res.tv_sec, 4);
      memcpy(bytes+ICMP_START+0x30, &usec, 4);
      clock_gettime(CLOCK_REALTIME, &res);
      // just for the sake of appearances
      sent = get_ts_utc(&res);
      memcpy(bytes+ICMP_START+16, &sent, 4);
      *(uint32_t*)(bytes+ICMP_START) = 0;
      // change to response
      bytes[ICMP_START] = 0x0e;
   } else {
      return; // do not process
   }
   // fix icmp header
   // recalculate checksum
   ip_checksum(bytes+ICMP_START, plen - ETH_HLEN - 4 - 20, (uint16_t*)(bytes+ICMP_START+2));
   // send packet
   send(fd, bytes, plen, 0);
//   clock_gettime(CLOCK_REALTIME, &res);
//   printf("%lu s %lu ns\n", res.tv_sec - res0.tv_sec, res.tv_nsec - res0.tv_nsec);   
}

void pak_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes)
{
   u_char response[1500];
   int fd;
   size_t plen;
   clock_gettime(CLOCK_REALTIME, &res0);

   //bin2hex(bytes, h->caplen);

   fd = *(int*)user;
   // expect vlan

   if (*(unsigned short*)(bytes+ETH_O_PROTO) != htons(ETH_P_8021Q)) return;   

   switch((*(unsigned short*)(bytes+ETH_O_PROTO+4))) {
     case 0x0008:
       plen = ntohs(*(unsigned short*)(bytes+IP_O_TOT_LEN))+ETH_HLEN+4; // total size of entire packet
       if (plen > 1500) return; // accept only 1500 byte packages
       memcpy(response,bytes,plen);

       // ensure dst ip is correct
       if (memcmp(response+IP_O_DADDR, &dest_ip, sizeof dest_ip)) return;

       switch(bytes[IP_O_PROTO]) {
         case 1:
            // it's icmp.
            process_and_send_icmp(fd,response,plen);
            break;
          case 17:
            // udp
            process_and_send_udp(fd,response,plen);
            break;
       }
       break;
     case 0x0608:
      // ensure request size.
      if (h->caplen < 46) return; // require 45 byte packet
      memcpy(response,bytes,h->caplen);
      process_and_send_arp(fd,response,h->caplen);
      break;
   }
}

void bpf_program(pcap_t *p, struct bpf_program *fp, char *ip)
{
  char errbuf[PCAP_ERRBUF_SIZE];
  char program[4096];
  snprintf(program, sizeof program, PCAP_FILTER_OWN_AND_ICMP_OR_UDP, ip);
  if (pcap_compile(p, fp, program, 1, PCAP_NETMASK_UNKNOWN) != 0) {
    pcap_perror(p, "pcap_compile");
    exit(1);
  } 
}

int getopt_responder(int argc, char * const argv[], uint32_t *ip, unsigned char *mac, int *verbose, char *interface, size_t iflen) 
{
  char opt;
  while((opt = getopt(argc, argv, "I:i:m:hv:")) != -1) {
     switch(opt) {
       case 'I':
         strncpy(interface, optarg, iflen);
         break;
       case 'i':
         if (inet_pton(AF_INET, optarg, ip) != 1) {
           fprintf(stderr, "Invalid IP address %s supplied\r\n", optarg);
           return EXIT_FAILURE;
         }
         break;
       case 'm': {
         /* convert by splitting, MAC must be ETH_ALEN long */
         char *ptr = optarg;
         char *optr = optarg;
         unsigned char *mptr = mac;
         size_t c = 0;
         while(optr != NULL && c++ < ETH_ALEN) {
            ptr = strchr(optr, ':');
            // happy windows users?
            if (ptr == NULL) ptr = strchr(optr, '-');
            sscanf(optr, "%02x", (unsigned int*)mptr++);
            if (ptr != NULL) ptr++;
            optr = ptr;
         }
         if (optr != NULL) {
            // duh. 
            fprintf(stderr, "Invalid MAC address %s supplied\r\n", optarg);
            return EXIT_FAILURE;
         }  
         break;
       }
       case 'v':
         *verbose = atoi(optarg);
         break;
       default:
         printf("Usage: responder -h -v level -I if -m mac -i ip\r\n");
         printf("\t-h      \t Help message\r\n");
         printf("\t-i ip   \t IP address to listen on (defaults to 192.168.0.1) \r\n");
         printf("\t-m mac  \t MAC address for IP (uses interface if empty)\r\n");
         printf("\t-I if   \t Interface to listen on (defaults to whatever pcap gives)\r\n");
         printf("\t-l level\t Message level (0-3, defaults to 0)\r\n");
         printf("\n");
         return EXIT_FAILURE;
     } 
  }
  return EXIT_SUCCESS;
}

int main(int argc, char * const argv[]) {
   int fd,n,valid_mac;
   struct ifreq ifr;
   struct sockaddr_ll sa;
   struct bpf_program fp;
   int val = 4;
   pcap_t *p;
   char errbuf[PCAP_ERRBUF_SIZE];
   char interface[IFNAMSIZ];
   char ipbuf[100];
   int debug;
   inet_pton(AF_INET, "62.236.255.178", &dest_ip);
   memset(dest_mac, 0, sizeof dest_mac);
   memset(interface, 0, sizeof interface);
   debug = 0;

   if (getopt_responder(argc, argv, &dest_ip, dest_mac, &debug, interface, IFNAMSIZ) != EXIT_SUCCESS) {
      return EXIT_FAILURE;
   }

   if (strlen(interface) == 0) {
     pcap_if_t *alldevsp, *devptr;
     if (pcap_findalldevs(&alldevsp, errbuf)) {
       fprintf(stderr, "pcap_findalldevs: %s\n", errbuf);
       return EXIT_FAILURE;
     }
     for(devptr = alldevsp; devptr != NULL; devptr = devptr->next) {
        if ((devptr->flags & PCAP_IF_LOOPBACK) == PCAP_IF_LOOPBACK) continue;
        // OK, this is our interface. 
        break; 
     }
     if (devptr == NULL) {
        fprintf(stderr, "cannot find suitable interface for operations\r\n");
        return EXIT_FAILURE;
     }
     strncpy(interface, devptr->name, sizeof interface);
     pcap_freealldevs(alldevsp);
   }

   fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
 
   // do we have a valid mac?
   for(n = 0; n < ETH_ALEN; n++) {
     valid_mac = dest_mac[n];
     if (valid_mac > 0) break;
   }

   if (valid_mac == 0) { 
     // need mac
     memset(&ifr,0,sizeof ifr);
     snprintf(ifr.ifr_name, IFNAMSIZ, interface);
     ioctl(fd, SIOCGIFHWADDR, &ifr);
     memcpy(dest_mac, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
   }

   inet_ntop(AF_INET, &dest_ip, ipbuf, sizeof ipbuf);
   memset(&ifr,0,sizeof ifr);
   snprintf(ifr.ifr_name, IFNAMSIZ, interface);
   ioctl(fd, SIOCGIFINDEX, &ifr);
   memset(&sa,0,sizeof sa);
   sa.sll_family = AF_PACKET;
   sa.sll_ifindex = ifr.ifr_ifindex;
   sa.sll_protocol = htons(ETH_P_ALL);
   bind(fd, (struct sockaddr*)&sa, sizeof sa);
   p = pcap_create(interface, errbuf);
   if (pcap_set_snaplen(p, 65535)) {
     pcap_perror(p, "pcap_set_snaplen");
     exit(1);
   }
   if (pcap_set_promisc(p, 1)) {
     pcap_perror(p, "pcap_set_promisc");
     exit(1);
   }
   // need to activate before setting datalink and filter
   pcap_activate(p);
   if (pcap_set_datalink(p, 1) != 0) {
     pcap_perror(p, "pcap_set_datalink");
     exit(1);
   }
   /*bpf_program(p, &fp,ipbuf);
   if (pcap_setfilter(p, &fp)!=0) {
     pcap_perror(p, "pcap_setfilter");
     exit(1);
   }*/
   printf("Listening on %s (mac: %02x:%02x:%02x:%02x:%02x:%02x ip: %s)\n", interface, dest_mac[0], dest_mac[1], dest_mac[2], dest_mac[3], dest_mac[4], dest_mac[5], ipbuf);

   pcap_loop(p, 0, pak_handler, (u_char*)&fd);
   pcap_close(p);

   return 0;
}
