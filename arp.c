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

int process_arp(u_char *buffer, size_t length, struct config_s *config) {
    u_char tmp[ETH_ALEN];
    size_t arp_start = ARP_START;

    if (config->vlan) arp_start += ETH_O_VLAN;

    if (*(uint16_t*)(buffer+arp_start)!=0x0100 ||     // hwtype ethernet
        *(uint16_t*)(buffer+arp_start+2)!=0x008 ||    // ethertype IP
        *(uint8_t*)(buffer+arp_start+4)!=0x06 ||      // hwlen 6
        *(uint8_t*)(buffer+arp_start+7)!=0x01 ||      // request
        *(uint32_t*)(buffer+arp_start+24)!=config->ip_addr.s_addr) { // our IP
      return -1; // ignore, not for us.
    }

    // check for broadcast
    if (!memcmp(buffer + ETH_O_SOURCE, "\xff\xff\xff\xff\xff\xff", ETH_ALEN)) 
       memcpy(buffer + ETH_O_SOURCE, config->mac, ETH_ALEN);
 
    // move sender to target, again
    memmove(buffer+arp_start+0x12, buffer+arp_start+0x8, ETH_ALEN+4);
    // fill in sender
    memcpy(buffer+arp_start+0x8, config->mac, ETH_ALEN);

    *(uint32_t*)(buffer+arp_start+0x8+ETH_ALEN) = config->ip_addr.s_addr;
    // make this response
    buffer[arp_start+0x7] = 0x02;

    // clean up response
    memset(buffer+arp_start+0x1c,0,18);
    return 0;
}
