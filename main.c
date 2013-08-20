/**
Copyright (c) 2012 Aki Tuomi <cmouse@cmouse.fi>

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be included
in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
**/

#include "responder.h"
#include <ctype.h>

void do_send(int fd, u_char *bytes, size_t plen)
{
   if (send(fd, bytes, plen, 0)<0) {
      perror("send");
   }
}

int configure(const char *file, struct config_s *config) {
   char buf[1024];
   FILE *f = fopen(file, "r");
   if (f == NULL) {
     fprintf(stderr, "Cannot open %s: ", file);
     perror("fopen");
     return -1;
   }

   // start reading
   while(!feof(f)) {
      memset(buf,0,sizeof buf);
      if (fgets(buf, sizeof buf, f) != NULL) {
        char *attribute,*value,*ptr3;
        attribute=buf;
        while(*attribute && isspace(*attribute)) attribute++;
        if (*attribute == '#' || 
            *attribute == '/' ||
            *attribute == 0) continue; // this is a comment or empty line

        value = attribute;
        while(*value && !isspace(*value)) value++;
        if (*value) *value = 0; // no more trailing whitespace
        value = strstr(attribute, "="); // look for separator
        *value=0;
        value++; // cut from here
        // trim attribute name
        ptr3 = attribute;
        while(*ptr3 && !isspace(*ptr3)) ptr3++;
        if (*ptr3) *ptr3 = 0; // no more trailing whitespace
        // trim attribute value
        while(*value && isspace(*value)) value++;

        // handle it
        if (!strcasecmp(attribute,"debuglevel")) {
          config->debuglevel = atoi(value);
          if (config->debuglevel < 0 || config->debuglevel > 2) {
             fprintf(stderr, "debuglevel must be 0,1 or 2\r\n");
             return -1;
          }
        } else if (!strcasecmp(attribute,"ipaddress")) {
          config->do_ip4 = 1;
          if (inet_pton(AF_INET, value, &config->ip_addr) != 1) {
              perror("inet_pton");
              return -1;
          }
        } else if (!strcasecmp(attribute,"ip6address")) {
          config->do_ip6 = 1;
          if (inet_pton(AF_INET6, value, &config->ip6_addr) != 1) {
              perror("inet_pton");
              return -1;
          }
        } else if (!strcasecmp(attribute,"iface")) {
          strncpy(config->ifname, value, IFNAMSIZ);
        } else if (!strcasecmp(attribute,"vlansupport")) {
          config->vlan = atoi(value);
          if (config->vlan < 0 || config->vlan > 1) {
             fprintf(stderr, "vlansupport must be 0 or 1\r\n");
             return -1;
          }
        } else if (!strcasecmp(attribute,"ciscoport")) {
          ptr3 = strstr(value,":");
          if (ptr3) {
              config->cisco_port_low = htons(atoi(value));
              config->cisco_port_high = htons(atoi(ptr3+1));
          } else {
              config->cisco_port_low = config->cisco_port_high = htons(atoi(value));
          }
        } else if (!strcasecmp(attribute,"mac")) {
          char *ptr,*optr;
          unsigned char *mptr = config->mac;
          size_t c = 0;
          ptr = optr = value;   
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
             return -1;
          }
        } else if (!strcasecmp(attribute,"check_address")) {
          if (!strcasecmp(value, "no") ||
              !strcasecmp(value, "off") ||
              !strcasecmp(value, "0")) {
              config->do_check_addr = 0;
          }
        }
      }
   }
   fclose(f);
   return 0;
}

void generate_ip6_values(struct config_s *config) {
   memcpy(config->mac6, "\x33\x33\xff\x00\x00\x00", ETH_ALEN);
   memcpy(config->mac6 + 3, config->ip6_addr.s6_addr + 13, 3);
   // use our MAC
   memcpy(config->link6_addr.s6_addr, "\xfe\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xfe\x00\x00\x00", 16);
   memcpy(config->link6_addr.s6_addr + 8, config->mac, 3);
   memcpy(config->link6_addr.s6_addr + 13, config->mac + 3, 3);
   // create multicast address
   memcpy(config->mc6_addr.s6_addr, "\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xff\x00\x00\x00\x00", 16);
   memcpy(config->mc6_addr.s6_addr + 13, config->ip6_addr.s6_addr + 13, 3);
}

/**
 * main(int argc, char * const argv[])
 *
 * program entry point
 */
int main(int argc, char * const argv[]) {
   struct config_s config;
   char errbuf[PCAP_ERRBUF_SIZE];
   struct ifreq ifr;
   struct sockaddr_ll sa;
   int n, valid_mac;
   int fd = 0;
   int runcond=1;
   pcap_t *p;

   memset(&config, 0, sizeof(config));
   
   config.vlan = 1;
   config.debuglevel = 0;
   config.cisco_port_low = config.cisco_port_high = htons(50505);
   config.do_check_addr = 1;
   fprintf(stderr,"IP SLA responder v2.0 (c) Aki Tuomi 2013-\r\n");
   fprintf(stderr,"See LICENSE for more information\r\n");

   if (argc == 2) {
    if (argv[1][0] != '-') {
      if (configure(argv[1], &config)) return -1;
    } else {
      fprintf(stderr,"Usage: %s [config file]\r\n\tDefaults to %s\r\n", argv[0], CONFIGFILE);
      return -1;
    }
   } else {
      if (configure(CONFIGFILE, &config)) return -1;
   }

   if (config.do_ip4) {
      if (config.do_check_addr) {
         char addr[200];
         inet_ntop(AF_INET, &config.ip_addr, addr, 200);
         fprintf(stderr, "Listening on %s %s:%u-%u\n", config.ifname, addr, ntohs(config.cisco_port_low), ntohs(config.cisco_port_high));
      } else {
          fprintf(stderr, "Listening on %s 0:0:0:0:%u-%u\n", config.ifname, ntohs(config.cisco_port_low), ntohs(config.cisco_port_high));
      }
   }
   if (config.do_ip6) {
      char addr[200];
      inet_ntop(AF_INET6, &config.ip6_addr, addr, 200);
      fprintf(stderr, "Listening on %s [%s]:%u-%u\n", config.ifname, addr, ntohs(config.cisco_port_low), ntohs(config.cisco_port_high));
   }
 
   // select first non-loopback if here
   if (strlen(config.ifname) == 0) {
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
     strncpy(config.ifname, devptr->name, sizeof(config.ifname));
     pcap_freealldevs(alldevsp);
   }

   // create raw socket
   fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

   // check for valid mac
   for(n = 0; n < ETH_ALEN; n++) {
     valid_mac = config.mac[n];
     if (valid_mac > 0) break;
   }

   if (valid_mac == 0) {
     // need mac from our interface
     memset(&ifr,0,sizeof ifr);
     strncpy(ifr.ifr_name, config.ifname, IFNAMSIZ);
     ioctl(fd, SIOCGIFHWADDR, &ifr);
     memcpy(config.mac, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
   }

   // get interface index for binding
   memset(&ifr,0,sizeof ifr);
   strncpy(ifr.ifr_name, config.ifname, IFNAMSIZ);
   ioctl(fd, SIOCGIFINDEX, &ifr);
   memset(&sa,0,sizeof sa);

   // bind our packet if to interface
   sa.sll_family = AF_PACKET;
   sa.sll_ifindex = ifr.ifr_ifindex;
   sa.sll_protocol = htons(ETH_P_ALL);
   bind(fd, (struct sockaddr*)&sa, sizeof sa);

   if (config.do_ip6)
      generate_ip6_values(&config);

   // initialize pcap
   p = pcap_create("eth1", errbuf);
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

   // start doing hard work
   while(runcond) {
      struct pak_handler_s tmp;
      tmp.config = &config;
      tmp.fd = fd;

      switch(pcap_dispatch(p, 0, pak_handler, (u_char*)&tmp)) {
      case -1:
         // ERROR!
         pcap_perror(p, "pcap_dispatch");
      case -2:
         // abort
         runcond = 0;
      } 
   }

   pcap_close(p);
   return 0;
}
