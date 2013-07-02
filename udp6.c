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

int process_udp6(u_char *buffer, size_t length, struct config_s *config, size_t ip6_start) {
   uint16_t tmp;

   if (process_cisco6(buffer, length, config, ip6_start) && 
       process_echo6(buffer, length, config, ip6_start)) return -1;

   tmp = *(uint16_t*)(buffer + UDP6_O_DSTPORT);
   *(uint16_t*)(buffer + UDP6_O_DSTPORT) = *(uint16_t*)(buffer + UDP6_O_SRCPORT);
   *(uint16_t*)(buffer + UDP6_O_SRCPORT) = tmp;

   *(uint16_t*)(buffer+UDP6_O_CHECKSUM) = 0;
   tcp6_checksum(buffer+IP6_O_SADDR, buffer+IP6_O_DADDR, 0x11, buffer+UDP6_START, ntohs(*(uint16_t*)(buffer+UDP6_O_LEN)), (uint16_t*)(buffer+UDP6_O_CHECKSUM));
   if (*(uint16_t*)(buffer+UDP6_O_CHECKSUM) == 0)
     *(uint16_t*)(buffer+UDP6_O_CHECKSUM) = 0xffff; 

   return 0;
}
