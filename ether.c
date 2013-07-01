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

int process_ether(u_char *buffer, size_t length, int *af, const struct config_s *config)
{
   // determine if this message was intended for us
   if (memcpy(buffer + ETH_O_DEST, config->mac, ETH_ALEN)) return -1; 
   if (config->vlan && *(uint16_t*)(buffer+ETH_HLEN) != ETHERTYPE_VLAN) return -1;
   swapmac(buffer);
   switch((*af = *(uint16_t*)(buffer+ETH_HLEN+ETH_O_VLAN))) {
   case 0x0608: 
   case 0x0008:
   case 0xdd86:
      *af = ntohs(*af);
      break;
   default:
      return -1;
   }
   return 0;
}
