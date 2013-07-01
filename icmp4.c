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

int process_icmp4(u_char *buffer, size_t length, struct config_s *config, size_t ip_start) {
   uint32_t tmp,recv;
   struct timespec res;
   size_t plen;

   plen = ntohs(*(uint16_t*)(buffer + IP_O_TOT_LEN)) - 20;
   recv = get_ts_utc(&config->res0);

   // check for ICMP type
   if (*(uint16_t*)(buffer+ICMP_START) == 8) { // icmp echo
     // this is simple ping, change it to response.
     *(uint32_t*)(buffer+ICMP_START) = 0;
   } else if (*(uint16_t*)(buffer+ICMP_START) == 0x000d) { // icmp timestamp
       if (length > 90 &&
           *(uint16_t*)(buffer+ICMP_DATA+0x1c) == 0x0100 &&
           *(uint16_t*)(buffer+ICMP_DATA+0x1e) == 0x1096) {
           // this is a juniper RPM format. we need to put here the recv/trans stamp too
           uint32_t usec,sent;
           // fill in received timestamp
           *(uint32_t*)(buffer+ICMP_DATA+0x4) = recv;
           // juniper uses uptime as epoch, we use something similar
           clock_gettime(CLOCK_MONOTONIC, &res);
           // put it in place
           *(uint32_t*)(buffer+ICMP_DATA+0x24) = htonl(res.tv_sec);
           *(uint32_t*)(buffer+ICMP_DATA+0x28) = htonl(res.tv_nsec/1000);
           // add transmit ts
           clock_gettime(CLOCK_REALTIME, &res);
           sent = get_ts_utc(&res);
           *(uint32_t*)(buffer+ICMP_DATA+0x08) = sent;
           // change to response
           buffer[ICMP_START] = 0x0e;
       } else {
           // handle as normal icmp timestamp request
           // fill in received and sent stamps
           // which should really be the same
           // but, well, maybe we got slow rtc?
           uint32_t sent;
           *(uint32_t*)(buffer+ICMP_DATA+0x4) = recv;
           clock_gettime(CLOCK_REALTIME, &res);
           sent = get_ts_utc(&res);
           *(uint32_t*)(buffer+ICMP_DATA+0x08) = sent;
           // change to response
           buffer[ICMP_START] = 0x0e;
       }
   } else {
      return -1; // do not process
   }

   // recalculate checksums
   *(uint16_t*)(buffer+ICMP_START+2)=0;
   ip_checksum(buffer+ICMP_START, plen, (uint16_t*)(buffer+ICMP_START+2)); 

   return 0;
}
