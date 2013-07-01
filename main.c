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

struct pak_handler_s {
  const struct config_s *config;
  int fd;
};

void pak_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
  u_char response[ETH_FRAME_LEN+1];
  int af;
  size_t plen;
  const struct pak_handler_s *pak_config = (struct pak_handler_s*)user;

  plen = (h->caplen > 1500 ? 1500 : h->caplen);
  memcpy(response, bytes, plen);
  if (process_ether(response, plen, &af, pak_config->config)) return; // ignore
}

 /**
 * main(int argc, char * const argv[])
 *
 * program entry point
 */
int main(int argc, char * const argv[]) {
   struct config_s config;
   char errbuf[PCAP_ERRBUF_SIZE];
   int fd = 0;
   int runcond=1;
   pcap_t *p;

   // initialize pcap
   p = pcap_create("eth0", errbuf);
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
