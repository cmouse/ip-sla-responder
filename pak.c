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

void pak_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
  u_char response[ETH_FRAME_LEN+1];
  int af;
  struct pak_handler_s *pak_config = (struct pak_handler_s*)user;
  clock_gettime(CLOCK_REALTIME, &pak_config->config->res0);

  pak_config->config->plen = (h->caplen > 1500 ? 1500 : h->caplen);

  memcpy(response, bytes, pak_config->config->plen);
  if (process_ether(response, pak_config->config->plen, &af, pak_config->config)) return; // ignore

  if (pak_config->config->debuglevel) {
    printf("Received %lu bytes\n", pak_config->config->plen);
    if (pak_config->config->debuglevel>1) bin2hex(bytes, pak_config->config->plen);
  }

  switch(af) {
  case ETHERTYPE_ARP:
    if (!pak_config->config->do_ip4 || process_arp(response, pak_config->config->plen, pak_config->config)) return; // ignore
    break;
  case ETHERTYPE_IP:
    if (!pak_config->config->do_ip4 || process_ip(response, pak_config->config->plen, pak_config->config)) return; // ignore
    break;
  case ETHERTYPE_IPV6:
    if (!pak_config->config->do_ip6 || process_ip6(response, pak_config->config->plen, pak_config->config)) return; // ignore
    break;
  }

  if (pak_config->config->debuglevel) {
    printf("Sent %lu bytes\n", pak_config->config->plen);
    if (pak_config->config->debuglevel>1) bin2hex(response, pak_config->config->plen);
  } 

  do_send(pak_config->fd, response, pak_config->config->plen);
}
