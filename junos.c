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

int process_echo4(u_char *buffer, size_t length, struct config_s *config, size_t ip_start) {
 struct timespec res;

 if (*(uint16_t*)(buffer+UDP_DPORT) == 0x0700) {  // htons(7)
      if (*(uint16_t*)(buffer+UDP_DATA+0x1c) == 0x0100 &&   // rpm signature
          *(uint16_t*)(buffer+UDP_DATA+0x1e) == 0x1096 && length > 90) {
         uint32_t usec,recv;
         // get time
         clock_gettime(CLOCK_REALTIME, &res);
         // convert into ms from midnight
         recv = get_ts_utc(&res);
         // put it in place, twice...
         *(uint32_t*)(buffer+UDP_DATA+0x4) = recv;
         *(uint32_t*)(buffer+UDP_DATA+0x8) = recv;
         // fill in little magic (dunno what this is for...)
         memcpy(buffer+UDP_DATA+0x14, "\xee\xdd\xcc\xbb\xaa\xcc\xdd\xee", 8);
         // juniper uses uptime as epoch, we use something similar
         clock_gettime(CLOCK_MONOTONIC, &res);
         // put in us accurate "uptime"
         *(uint32_t*)(buffer+UDP_DATA+0x24) = htonl(res.tv_sec);
         *(uint32_t*)(buffer+UDP_DATA+0x28) = htonl(res.tv_nsec/1000);
      } else { 
         // treat as normal ECHO - do nothing to it.
      } 
      return 0;
 }
 return -1;
}

int process_echo6(u_char *buffer, size_t length, struct config_s *config, size_t ip6_start) {
 struct timespec res;

 if (*(uint16_t*)(buffer+UDP6_O_DSTPORT) == 0x0700) {  // htons(7)
      if (*(uint16_t*)(buffer+UDP6_O_DATA+0x1c) == 0x0100 &&   // rpm signature
          *(uint16_t*)(buffer+UDP6_O_DATA+0x1e) == 0x1096 && length > UDP6_O_DATA + 44) {
         uint32_t usec,recv;
         // get time
         clock_gettime(CLOCK_REALTIME, &res);
         // convert into ms from midnight
         recv = get_ts_utc(&res);
         // put it in place, twice...
         *(uint32_t*)(buffer+UDP6_O_DATA+0x4) = recv;
         *(uint32_t*)(buffer+UDP6_O_DATA+0x8) = recv;
         // fill in little magic (dunno what this is for...)
         memcpy(buffer+UDP6_O_DATA+0x14, "\xee\xdd\xcc\xbb\xaa\xcc\xdd\xee", 8);
         // juniper uses uptime as epoch, we use something similar
         clock_gettime(CLOCK_MONOTONIC, &res);
         // put in our accurate "uptime"
         *(uint32_t*)(buffer+UDP6_O_DATA+0x24) = htonl(res.tv_sec);
         *(uint32_t*)(buffer+UDP6_O_DATA+0x28) = htonl(res.tv_nsec/1000);
      } else {
         // treat as normal ECHO - do nothing to it.
      }
      return 0;
 }
 return -1;
}
