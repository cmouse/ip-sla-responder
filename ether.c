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

inline void swapmac(u_char *bytes) {
   u_char etmp[ETH_ALEN];
   memcpy(etmp, bytes, ETH_ALEN);
   memmove(bytes, bytes+ETH_ALEN, ETH_ALEN);
   memcpy(bytes+ETH_ALEN, etmp, ETH_ALEN);
}

int process_ether(u_char *buffer, size_t length, int *af, struct config_s *config)
{
   // determine if this message was intended for us
/*   printf("MAC check (got %02x:%02x:%02x:%02x:%02x:%02x) wanted (%02x:%02x:%02x:%02x:%02x:%02x)\n", 
      buffer[0], buffer[1], buffer[2], buffer[3], buffer[4], buffer[5],
      config->mac[0], config->mac[1], config->mac[2], config->mac[3],
      config->mac[4], config->mac[5]); */

   if (memcmp(buffer + ETH_O_DEST, config->mac, ETH_ALEN) &&
       memcmp(buffer + ETH_O_DEST, "\xff\xff\xff\xff\xff\xff", ETH_ALEN)) return -1; // broadcast case

   if (config->vlan && *(uint16_t*)(buffer+ETH_O_PROTO) != 0x0081) return -1;

   swapmac(buffer);
   switch((*af = *(uint16_t*)(buffer+ETH_O_PROTO+ETH_O_VLAN))) {
   case 0x0608: 
   case 0x0008:
   case 0xdd86:
      *af = ntohs(*af);
      break;
   default:
      printf("Packet with %04x AF\n", *af);
      return -1;
   }
   return 0;
}
