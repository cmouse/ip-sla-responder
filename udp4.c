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

   
int process_udp4(u_char *buffer, size_t length, struct config_s *config, size_t ip_start) {
   uint16_t tmp;

   if (process_cisco4(buffer, length, config, ip_start) && 
       process_echo4(buffer, length, config, ip_start)) return -1;

   // port swap
   tmp = *(uint16_t*)(buffer + UDP_DPORT);
   *(uint16_t*)(buffer + UDP_DPORT) = *(uint16_t*)(buffer + UDP_SPORT);
   *(uint16_t*)(buffer + UDP_SPORT) = tmp;

   *(uint16_t*)(buffer+UDP_CHECKSUM) = 0;
   tcp4_checksum(buffer+IP_O_SADDR, buffer+IP_O_DADDR, 0x11, buffer+UDP_START, ntohs(*(uint16_t*)(buffer+UDP_LEN)), (uint16_t*)(buffer+UDP_CHECKSUM));
   if (*(uint16_t*)(buffer+UDP_CHECKSUM) == 0)
     *(uint16_t*)(buffer+UDP_CHECKSUM) = 0xffff; 

   return 0;

}
