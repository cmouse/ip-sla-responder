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

int process_cisco4(u_char *buffer, size_t length, struct config_s *config, size_t ip_start) {
   struct timespec res;

   if (*(uint16_t*)(buffer+UDP_DPORT) == 0xaf07  && length > 23) { // port 1967
      // this is probably cisco ipsla.
      if (*(uint8_t*)(buffer+UDP_DATA) == 0x01 &&                // version = 1
          *(uint16_t*)(buffer+UDP_DATA+0x14) == config->cisco_port) { // target port = our preselected port
         // truncate packet
         *(uint16_t*)(buffer+IP_O_TOT_LEN) = 0x3400; // htons(52)
         *(uint16_t*)(buffer+UDP_LEN) = 0x2000; //  htons(32)
         config->plen = UDP_DATA+24;
         // change to something 8 zeros
         buffer[UDP_DATA+0x3] = 0x08;
         memset(buffer+UDP_DATA+0x4, 0, 8);
      } else {
         if (config->debuglevel) {
            printf("Ignored packet to udp/1967, did not contain cisco ipsla init\n");
         }
         return -1; // ignore this
      }
   } else if (*(uint16_t*)(buffer+UDP_DPORT) == config->cisco_port && length > UDP_DATA + 31) {
      clock_gettime(CLOCK_REALTIME, &res);
      if (buffer[UDP_DATA+0x1] == 0x02) {
        // fill in ms accurate time from midnight, aka ICMP timestamp
        *(uint32_t*)(buffer + UDP_DATA + 0x8) = htonl(get_ts_utc(&res));
        // copy packet sequence number
        *(uint16_t*)(buffer + UDP_DATA + 0x0e) = *(uint16_t*)(buffer + UDP_DATA + 0x0c);
      } else if (buffer[UDP_DATA+0x1] == 0x03) {
         uint32_t t2, t3;
         // generate received ntp timestamp
         ts_to_ntp(&config->res0, &t2, &t3);
         // put it in place
         *(uint32_t*)(buffer+UDP_DATA+0xc) = t2;
         *(uint32_t*)(buffer+UDP_DATA+0x10) = t3;
         // generate about-to-send ntp timestamp
         ts_to_ntp(&res, &t2, &t3);
         // put it in place
         *(uint32_t*)(buffer+UDP_DATA+0x14) = t2;
         *(uint32_t*)(buffer+UDP_DATA+0x18) = t3;
         // copy packet sequence number
         *(uint16_t*)(buffer+UDP_DATA+0x36) = *(uint16_t*)(buffer+UDP_DATA+0x34);
         // fill out some cisco specific cruft
         memcpy(buffer+0x52, "\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x00", 11);
      } else {
         if (config->debuglevel) {
            printf("Ignored packet to udp/%u, did not contain cisco ipsla\n", ntohs(config->cisco_port));
         }
         return -1;
      }
   }
   return 0;
}
