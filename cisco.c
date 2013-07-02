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
          *(uint16_t*)(buffer+UDP_DATA+0x14) >= config->cisco_port_low &&
          *(uint16_t*)(buffer+UDP_DATA+0x14) <= config->cisco_port_high) { // target port = our preselected port
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
      return 0;
   } else if (*(uint16_t*)(buffer+UDP_DPORT) == config->cisco_port_low && 
              *(uint16_t*)(buffer+UDP_DPORT) == config->cisco_port_high &&
              length > UDP_DATA + 31) {
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
            printf("Ignored packet to udp/%u, did not contain cisco ipsla\n", ntohs(*(uint16_t*)(buffer+UDP_DPORT)));
         }
         return -1;
      }
      return 0;
   }
   return -1;
}

/*
0000  d0 d0 fd 09 34 2d 88 43 e1 de 22 c0 81 00 00 ce
0010  86 dd 60 00 00 00 00 4c 11 3f 20 01 06 e8 06 04
0020  ff ff 1e df 0f ff fe 46 a7 68 20 01 06 e8 02 80
0030  00 00 00 00 00 00 00 01 34 2d cf a0 07 af 00 4c
0040  88 f6 01 3c 00 44 00 00 00 00 00 08 00 20 00 00
0050  00 00 20 01 06 e8 02 80 00 00 00 00 00 00 00 01
0060  34 2d c5 49 00 00 00 00 1b 58 00 01 00 1c 00 00
0070  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0080  00 00 00 00 00 00

0000  d0 d0 fd 09 34 2d 88 43 e1 de 22 c0 81 00 20 ce
0010  86 dd 62 00 00 00 01 08 11 3f 20 01 06 e8 06 04
0020  ff ff 1e df 0f ff fe 46 a7 68 20 01 06 e8 02 80
0030  00 00 00 00 00 00 00 01 34 2d dd 4c c5 49 01 08
0040  f3 39 00 02 00 00 01 e1 7e 53 00 00 00 00 00 5d
0050  00 00 ab cd ab cd ab cd ab cd ab cd ab cd ab cd
0060  ab cd ab cd ab cd ab cd ab cd ab cd ab cd ab cd
0070  ab cd ab cd ab cd ab cd ab cd ab cd ab cd ab cd
0080  ab cd ab cd ab cd ab cd ab cd ab cd ab cd ab cd
0090  ab cd ab cd ab cd ab cd ab cd ab cd ab cd ab cd
00a0  ab cd ab cd ab cd ab cd ab cd ab cd ab cd ab cd
00b0  ab cd ab cd ab cd ab cd ab cd ab cd ab cd ab cd
00c0  ab cd ab cd ab cd ab cd ab cd ab cd ab cd ab cd
00d0  ab cd ab cd ab cd ab cd ab cd ab cd ab cd ab cd
00e0  ab cd ab cd ab cd ab cd ab cd ab cd ab cd ab cd
00f0  ab cd ab cd ab cd ab cd ab cd ab cd ab cd ab cd
0100  ab cd ab cd ab cd ab cd ab cd ab cd ab cd ab cd
0110  ab cd ab cd ab cd ab cd ab cd ab cd ab cd ab cd
0120  ab cd ab cd ab cd ab cd ab cd ab cd ab cd ab cd
0130  ab cd ab cd ab cd ab cd ab cd ab cd ab cd ab cd
0140  ab cd
*/

int process_cisco6(u_char *buffer, size_t length, struct config_s *config, size_t ip6_start) {
   struct timespec res;

   if (*(uint16_t*)(buffer+UDP6_O_DSTPORT) == 0xaf07  && length > 133) { // port 1967
      // this is probably cisco ipsla.
      if (*(uint8_t*)(buffer+UDP6_O_DATA) == 0x01 &&                // version = 1
          *(uint16_t*)(buffer+UDP6_O_DATA+0x20) >= config->cisco_port_low &&
          *(uint16_t*)(buffer+UDP6_O_DATA+0x20) <= config->cisco_port_high) { // target port = our preselected port
         // truncate packet
/*         *(uint16_t*)(buffer+IP6_O_LEN) = 0x4c00; // htons(76)
         *(uint16_t*)(buffer+UDP6_O_LEN) = 0x4c00; //  htons(76)
         config->plen = UDP6_O_DATA+68;
         // change to something 8 zeros
         buffer[UDP6_O_DATA+0x3] = 0x08;
         memset(buffer+UDP6_O_DATA+0x4, 0, 8);*/
	 // do nothing for now... 
      } else {
         if (config->debuglevel) {
            printf("Ignored packet to udp/1967, did not contain cisco ipsla init (version=%u, port=%u)\n", *(uint8_t*)(buffer+UDP6_O_DATA), ntohs( *(uint16_t*)(buffer+UDP6_O_DATA+0x1e)));
         }
         return -1; // ignore this
      }
      return 0;
   } else if (*(uint16_t*)(buffer+UDP6_O_DSTPORT) >= config->cisco_port_low &&
              *(uint16_t*)(buffer+UDP6_O_DSTPORT) <= config->cisco_port_high &&
              length > UDP6_O_DATA + 31) {
      clock_gettime(CLOCK_REALTIME, &res);
      if (buffer[UDP6_O_DATA+0x1] == 0x01) {
        // do nothing? 
      } else if (buffer[UDP6_O_DATA+0x1] == 0x02) {
        // fill in ms accurate time from midnight, aka ICMP timestamp
        *(uint32_t*)(buffer + UDP6_O_DATA + 0x08) = htonl(get_ts_utc(&res));
        // copy packet sequence number
        *(uint16_t*)(buffer + UDP6_O_DATA + 0x0e) = *(uint16_t*)(buffer + UDP6_O_DATA + 0x0c);
      } else if (buffer[UDP6_O_DATA+0x1] == 0x03) {
         uint32_t t2, t3;
         // generate received ntp timestamp
         ts_to_ntp(&config->res0, &t2, &t3);
         // put it in place
         *(uint32_t*)(buffer+UDP6_O_DATA+0xc) = t2;
         *(uint32_t*)(buffer+UDP6_O_DATA+0x10) = t3;
         // generate about-to-send ntp timestamp
         ts_to_ntp(&res, &t2, &t3);
         // put it in place
         *(uint32_t*)(buffer+UDP6_O_DATA+0x14) = t2;
         *(uint32_t*)(buffer+UDP6_O_DATA+0x18) = t3;
         // copy packet sequence number
         *(uint16_t*)(buffer+UDP6_O_DATA+0x36) = *(uint16_t*)(buffer+UDP6_O_DATA+0x34);
         // fill out some cisco specific cruft
         memcpy(buffer+0x52, "\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x00", 11);
      } else {
         if (config->debuglevel) {
            printf("Ignored packet to udp/%u, did not contain cisco ipsla\n", ntohs(*(uint16_t*)(buffer+UDP6_O_DSTPORT+0x20)));
         }
         return -1;
      }
      return 0;
   }
   return -1;
}
