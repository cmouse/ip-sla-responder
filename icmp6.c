/**
 * Copyright (c) 2012 Aki Tuomi <cmouse@cmouse.fi>
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 * **/

#include "responder.h"

#define ICMP6_O_TYPE (ip6_start + 40)
#define ICMP6_O_CODE (ICMP6_O_TYPE + 1)
#define ICMP6_O_CHKSUM (ICMP6_O_TYPE + 2)
#define ICMP6_O_DATA (ICMP6_O_TYPE + 4)

int process_icmp6(u_char *buffer, size_t length, struct config_s *config, size_t ip6_start) {
   size_t plen;
 
   plen = ntohs(*(uint16_t*)(buffer + IP6_O_LEN));

   switch(buffer[ICMP6_O_TYPE]) {
   case 0x80: // icmp echo request
      buffer[ICMP6_O_TYPE] = 0x81; // reply
      break; 
   case 0x87: // v6 ndp
     buffer[ICMP6_O_TYPE] = 0x88; // reply
     buffer[ICMP6_O_CODE] = 0x0; 
      *(uint32_t*)(buffer+ICMP6_O_DATA) = 0x40; // solicited
      memcpy(buffer + ETH_O_SOURCE, config->mac, ETH_ALEN);
      memcpy(buffer + IP6_O_DADDR, config->ip6_addr.s6_addr, 16);
      memcpy(buffer + ICMP6_O_DATA + 4, config->ip6_addr.s6_addr, 16); 
      memcpy(buffer + ICMP6_O_DATA + 22, config->mac, 6);
      buffer[ICMP6_O_DATA + 20] = 2;
      break;
   default:
      return -1;   
   };

   *(uint16_t*)(buffer + ICMP6_O_CHKSUM)=0;
   tcp6_checksum(buffer + IP6_O_SADDR, buffer + IP6_O_DADDR, 0x3A, buffer + ICMP6_O_TYPE, plen, (uint16_t*)(buffer + ICMP6_O_CHKSUM)); 

   return 0;
}
