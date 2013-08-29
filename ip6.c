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

int process_ip6(u_char *buffer, size_t length, struct config_s *config) {
  u_char tmp[16];
  char addr[200];

  size_t ip6_start = IP6_START;
  if (config->vlan) ip6_start += ETH_O_VLAN;
  
  // check for IPv6
  if ((buffer[ip6_start] & 0xF0) != 0x60) return -1;
  
  // check if it's for us
  if (memcmp(buffer + IP6_O_DADDR, config->link6_addr.s6_addr, 16) &&
      memcmp(buffer + IP6_O_DADDR, config->mc6_addr.s6_addr, 16)) {
      // FIXME: IPv6 do_check_addr support
      if (memcmp(buffer + IP6_O_DADDR, config->ip6_addr.s6_addr, 16)) return -1;
  }

  // choose protocol by next header
  // ANY EXTENSION HEADERS WILL CAUSE PACKET TO BE DROPPED
  switch(buffer[IP6_O_NH]) {
  case 0x3A: // icmpv6
    if (process_icmp6(buffer, length, config, ip6_start)) return -1;
    break;
  case 0x11: // udp 
    if (process_udp6(buffer, length, config, ip6_start)) return -1;
    break;
  default:
    if (config->debuglevel)
      printf("Ignoring IPv6 protocol %02x at %04lx\n", *(uint8_t*)(buffer + IP6_O_NH), IP6_O_NH);
    return -1;
  }

  // swap IP addresses
  memcpy(tmp, buffer + IP6_O_SADDR, 16);
  memmove(buffer + IP6_O_SADDR, buffer + IP6_O_DADDR, 16);
  memcpy(buffer + IP6_O_DADDR, tmp, 16); 

  // ipv6 has no checksum on ip header
  return 0;
}
