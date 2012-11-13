#include "responder.c"

/**
 * getopt_responder(int argc, char * const argv[], uint32_t *ip, unsigned char *mac, int *verbose, 
 * uint16_t *port_udp_ip_sla, char *interface, size_t iflen)
 *
 * handles command line parameters.
 *
 * @param argc - n. of arguments given
 * @param aggv - actual arguments
 * @param ip - pointer to IPv4 address storage
 * @param mac - pointer to MAC storage
 * @param verbose - pointer to store debug level
 * @param port_udp_ip_sla - pointer to store IP SLA port number
 * @param interface - pointer to store interface name
 * @param iflen - size of interface name storage
 *
 * @returns 0 on success, non-zero on failure
 */
int getopt_responder(int argc, char * const argv[], uint32_t *ip, unsigned char *mac, int *verbose, 
                     uint16_t *port_udp_ip_sla, char *interface, size_t iflen) {
  char opt;
  while((opt = getopt(argc, argv, "p:I:i:m:hv:")) != -1) {
     switch(opt) {
       // interface
       case 'I':
         strncpy(interface, optarg, iflen);
         break;
       // ip sla port
       case 'p':
         *port_udp_ip_sla = htons((uint16_t)atoi(optarg));
         if (*port_udp_ip_sla == 0) {
           fprintf(stderr, "Invalid UDP port for IP-SLA supplied: %s\r\n", optarg);
           return EXIT_FAILURE;
         }
         break;
       // ip address
       case 'i':
         if (inet_pton(AF_INET, optarg, ip) != 1) {
           fprintf(stderr, "Invalid IP address %s supplied\r\n", optarg);
           return EXIT_FAILURE;
         }
         break;
       // mac address
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
       //debug level
       case 'v':
         *verbose = atoi(optarg);
         break;
       default:
         printf("Usage: responder -h -v level -I if -m mac -i ip\r\n");
         printf("\t-h      \t Help message\r\n");
         printf("\t-i ip   \t IP address to listen on (defaults to 192.168.0.1) \r\n");
         printf("\t-m mac  \t MAC address for IP (uses interface's if empty)\r\n");
         printf("\t-I if   \t Interface to listen on (defaults to first non-loopback interface)\r\n");
         printf("\t-l level\t Message level (0-1, defaults to 0)\r\n");
         printf("\t-p port \t UDP port for Cisco IP SLA (default 50505)\r\n");
         printf("\n");
         return EXIT_FAILURE;
     } 
  }
  return EXIT_SUCCESS;
}

/**
 * main(int argc, char * const argv[])
 *
 * program entry point
 */
int main(int argc, char * const argv[]) {
   int fd,n,valid_mac;
   struct ifreq ifr;
   struct sockaddr_ll sa;
   pcap_t *p;
   char errbuf[PCAP_ERRBUF_SIZE];
   char interface[IFNAMSIZ];
   char ipbuf[100];

   // default IP address
   inet_pton(AF_INET, DEFAULT_IP_ADDR, &dest_ip);
   // sanitize and default
   memset(dest_mac, 0, sizeof dest_mac);
   memset(interface, 0, sizeof interface);
   debuglevel = 0;
   dest_udp_ip_sla = htons(DEFAULT_IPSLA_PORT);
   // parse command line args
   if (getopt_responder(argc, argv, &dest_ip, dest_mac, &debuglevel, &dest_udp_ip_sla, interface, IFNAMSIZ) != EXIT_SUCCESS) {
      return EXIT_FAILURE;
   }
 
   // select first non-loopback if here
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

   // create raw socket
   fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
 
   // check for valid mac
   for(n = 0; n < ETH_ALEN; n++) {
     valid_mac = dest_mac[n];
     if (valid_mac > 0) break;
   }

   if (valid_mac == 0) { 
     // need mac from our interface
     memset(&ifr,0,sizeof ifr);
     strncpy(ifr.ifr_name, interface, IFNAMSIZ);
     ioctl(fd, SIOCGIFHWADDR, &ifr);
     memcpy(dest_mac, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
   }

   // parse IP address into uint32_t
   inet_ntop(AF_INET, &dest_ip, ipbuf, sizeof ipbuf);

   // get interface index for binding
   memset(&ifr,0,sizeof ifr);
   strncpy(ifr.ifr_name, interface, IFNAMSIZ);
   ioctl(fd, SIOCGIFINDEX, &ifr);
   memset(&sa,0,sizeof sa);

   // bind our packet if to interface
   sa.sll_family = AF_PACKET;
   sa.sll_ifindex = ifr.ifr_ifindex;
   sa.sll_protocol = htons(ETH_P_ALL);
   bind(fd, (struct sockaddr*)&sa, sizeof sa);

   // initialize pcap
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
   printf("Listening on %s (mac: %02x:%02x:%02x:%02x:%02x:%02x ip: %s)\n", interface, dest_mac[0], dest_mac[1], dest_mac[2], dest_mac[3], dest_mac[4], dest_mac[5], ipbuf);

   // start doing hard work
   pcap_loop(p, 0, pak_handler, (u_char*)&fd);
   pcap_close(p);

   return 0;
}
