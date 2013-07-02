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

void do_send(int fd, u_char *bytes, size_t plen)
{
   if (send(fd, bytes, plen, 0)<0) {
      perror("send");
   }
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
   int fd = 0;
   int runcond=1;
   pcap_t *p;

   memcpy(config.mac, "\xd0\xd0\xfd\x09\x34\x2d", ETH_ALEN);
   
   inet_pton(AF_INET, "195.10.131.29", &config.ip_addr); 
   inet_pton(AF_INET6, "2001:6E8:280::1:342d", &config.ip6_addr);
   
   memcpy(config.mac6, "\x33\x33\xff\x00\x00\x00", ETH_ALEN);
   memcpy(config.mac6 + 3, config.ip6_addr.s6_addr + 13, 3);
 
   // use our MAC 
   memcpy(config.link6_addr.s6_addr, "\xfe\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xfe\x00\x00\x00", 16);
   memcpy(config.link6_addr.s6_addr + 8, config.mac, 3);
   memcpy(config.link6_addr.s6_addr + 13, config.mac + 3, 3);
   // create multicast address
   memcpy(config.mc6_addr.s6_addr, "\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xff\x00\x00\x00\x00", 16);
   memcpy(config.mc6_addr.s6_addr + 13, config.ip6_addr.s6_addr + 13, 3);

   config.vlan = 1;
   config.debuglevel = 2;
   config.cisco_port = htons(50505);

   fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
   memset(&ifr,0,sizeof ifr);
   strncpy(ifr.ifr_name, "eth1", IFNAMSIZ);
   ioctl(fd, SIOCGIFINDEX, &ifr);
   memset(&sa,0,sizeof sa);

   // bind our packet if to interface
   sa.sll_family = AF_PACKET;
   sa.sll_ifindex = ifr.ifr_ifindex;
   sa.sll_protocol = htons(ETH_P_ALL);
   bind(fd, (struct sockaddr*)&sa, sizeof sa);  

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
