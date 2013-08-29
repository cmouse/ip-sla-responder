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

int process_ip(u_char *buffer, size_t length, struct config_s *config) {
  // ensure we have IP
  uint32_t tmp;
  
  size_t ip_start = IP_START;
  if (config->vlan) ip_start += ETH_O_VLAN;
  if (buffer[ip_start] != IP_MAGIC) return -1;
  
  // targeted to us? do we even care?
  if (config->do_check_addr && *(uint32_t*)(buffer + IP_O_DADDR) != config->ip_addr.s_addr) return -1;

  uint16_t frag = ntohs(*(uint16_t*)(buffer+IP_O_FRAG_OFF));

  if ((frag & 0xE000) == 0x2000 ||
       (frag & 0x1FFF) > 0 ) {
     // ignore packet with more fragment flag or fragment offset > 1
     return -1;
  }

  // determine protocol
  switch(*(uint8_t*)(buffer + IP_O_PROTO)) {
  case 0x1:
    // icmp
    if (process_icmp4(buffer, length, config, ip_start)) return -1;
    break;
  case 0x11:
    // udp 
    if (process_udp4(buffer, length, config, ip_start)) return -1;
    break;
  default:
    if (config->debuglevel) 
       printf("Ignoring IP protocol %02x at %04lx\n", *(uint8_t*)(buffer + IP_O_PROTO), IP_O_PROTO);
    return -1;
  }

  tmp = *(uint32_t*)(buffer+IP_O_SADDR);
  *(uint32_t*)(buffer+IP_O_SADDR) = *(uint32_t*)(buffer+IP_O_DADDR);
  *(uint32_t*)(buffer+IP_O_DADDR) = tmp;
  *(uint16_t*)(buffer+IP_O_CHKSUM)=0;
  ip_checksum(buffer+ip_start, 20, (uint16_t*)(buffer+IP_O_CHKSUM));

  return 0;
}
