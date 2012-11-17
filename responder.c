/**
Copyright (c) 2012, Aki Tuomi <cmouse@cmouse.fi>
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

 *  Redistributions of source code must retain the above copyright notice, this
    list of conditions and the following disclaimer.
 *  Redistributions in binary form must reproduce the above copyright notice, 
    this list of conditions and the following disclaimer in the documentation 
    and/or other materials provided with the distribution.
 *  Neither the name of the <ORGANIZATION> nor the names of its contributors 
    may be used to endorse or promote products derived from this software 
    without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/
 
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <net/ethernet.h> 
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <pcap/pcap.h>
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>
#include <netpacket/packet.h>
#include <time.h>

#define ETH_O_DEST 0
#define ETH_O_SOURCE 6
#define ETH_O_PROTO 12

#ifdef HAS_VLAN
#define ETH_O_VLAN 4
#else
#define ETH_O_VLAN 0
#endif

#define IP_MAGIC 45

#define IP_START (ETH_HLEN+ETH_O_VLAN)
#define IP_O_TOS (IP_START+1)
#define IP_O_TOT_LEN (IP_START+2)
#define IP_O_ID (IP_START+4)
#define IP_O_FRAG_OFF (IP_START+6)
#define IP_O_TTL (IP_START+8)
#define IP_O_PROTO (IP_START+9)
#define IP_O_CHKSUM (IP_START+10)
#define IP_O_SADDR (IP_START+12)
#define IP_O_DADDR (IP_START+16)

#define ICMP_START (IP_START+20)
#define ICMP_DATA (ICMP_START+8)

#define UDP_START (IP_START+20)
#define UDP_SPORT (UDP_START)
#define UDP_DPORT (UDP_START+2)
#define UDP_LEN (UDP_START+4)
#define UDP_CHECKSUM (UDP_START+6)
#define UDP_DATA (UDP_START+8)

#define ARP_START (ETH_HLEN+4)

#define DEFAULT_IP_ADDR "192.168.0.2"
#define DEFAULT_IPSLA_PORT 50505

struct timespec res0;
static uint32_t dest_ip;
static uint16_t dest_udp_ip_sla;
static u_char dest_mac[ETH_ALEN];
static int debuglevel;

const unsigned long NTP_EPOCH = 2208988800UL;
const unsigned long NTP_SCALE_FRAC = 4294967296UL;

inline uint32_t get_ts_utc(struct timespec *res) {
   struct tm tm;
   gmtime_r(&(res->tv_sec), &tm);
   return (tm.tm_hour*3600+tm.tm_min*60+tm.tm_sec)*1000 + (res->tv_nsec/1000000);
}

inline void ts_to_ntp(const struct timespec *res, uint32_t *ntp_sec, uint32_t *ntp_fsec) {
    *ntp_sec = htonl(res->tv_sec + NTP_EPOCH);
    *ntp_fsec = htonl(((NTP_SCALE_FRAC * (res->tv_nsec/1000)) / 1000000UL));
}

void bin2hex(const unsigned char *data, size_t dlen) {
   size_t i;
   for(i=0; i < dlen; i++) {
     if ((i % 16) == 0 || i == 0)
      printf("\n%04x  ", (unsigned int)i);
     printf("%02x ", data[i]);
   }
   printf("\n");
}

inline uint16_t ip_checksum(const void *vdata, size_t dlen, uint16_t *target) {
   register uint16_t word16;
   register uint32_t sum=0;
   register size_t i;
   const unsigned char *buff = (const unsigned char *)vdata;

   // make 16 bit words out of every two adjacent 8 bit words in the packet
   // and add them up
   for (i=0;i<dlen-1;i=i+2){
     word16 =((buff[i]<<8)&0xff00)+(buff[i+1]&0xff);
     sum += (uint32_t) word16;	
   }
   if (i != dlen) sum += buff[dlen-1]&0xff;

   // take only 16 bits out of the 32 bit sum and add up the carries
   sum = (sum & 0xffff)+(sum >> 16);
   sum += (sum >> 16);

   // one's complement the result
   sum = ~sum;
   
   (*target) = htons(((uint16_t)sum));
   return *target;
}

inline uint16_t tcp_checksum(const u_char *src_addr, const u_char *dest_addr, u_char *buff, size_t dlen, uint16_t *target) {
   register uint16_t word16;
   register uint32_t sum=0;
   register size_t i;
   uint16_t pad;

   pad=dlen&1;
   buff[dlen]=0; // this will work in this code...

   for (i=0;i<dlen+pad;i=i+2){
     word16 =((buff[i]<<8)&0xff00)+(buff[i+1]&0xff);
     sum += (uint32_t)word16;
   }
   for (i=0;i<4;i=i+2){
     word16 =((src_addr[i]<<8)&0xFF00)+(src_addr[i+1]&0xFF);
     sum += (uint32_t)word16;
   }
   for (i=0;i<4;i=i+2){
     word16 =((dest_addr[i]<<8)&0xFF00)+(dest_addr[i+1]&0xFF);
     sum += (uint32_t)word16;
   }
   sum = sum + 17 + dlen;
   sum = (sum & 0xffff)+(sum >> 16);
   sum += (sum >> 16);
   sum = ~sum;
   (*target) = htons(((uint16_t)sum));
   return *target;
}

inline void swapmac(u_char *bytes) {
   u_char etmp[ETH_ALEN];
   memcpy(etmp, bytes, ETH_ALEN);
   memmove(bytes, bytes+ETH_ALEN, ETH_ALEN);
   memcpy(bytes+ETH_ALEN, etmp, ETH_ALEN);
}

inline void swapip(u_char *bytes) {
   uint32_t tmp;
   tmp = *(uint32_t*)(bytes+IP_O_SADDR);
   *(uint32_t*)(bytes+IP_O_SADDR) = *(uint32_t*)(bytes+IP_O_DADDR);
   *(uint32_t*)(bytes+IP_O_DADDR) = tmp;
} 

/**
 * process_and_send_arp(int fd, u_char *bytes, size_t plen)
 * 
 * responsible for sending ARP respondes for our virtual IP.
 *
 * @param fd - File descriptor to send response to
 * @param bytes - Received bytes and working area
 * @param plen - Length of received packet
 */
void process_and_send_arp(int fd, u_char *bytes, size_t plen) {
    u_char tmp[ETH_ALEN];

   if (debuglevel) {
     printf("Received %lu bytes\n", plen);
     bin2hex(bytes, plen);
   }

    if (*(uint16_t*)(bytes+ARP_START)!=0x0100 ||     // hwtype ethernet
        *(uint16_t*)(bytes+ARP_START+2)!=0x008 ||    // ethetype IP
        *(uint8_t*)(bytes+ARP_START+4)!=0x06 ||      // hwlen 6
        *(uint8_t*)(bytes+ARP_START+7)!=0x01 ||      // request
        *(uint32_t*)(bytes+ARP_START+24)!=dest_ip) { // our IP
      return; // ignore, not for us. 
    }

    // move sender to target
    memmove(bytes, bytes+ETH_ALEN, ETH_ALEN);
    // in case it's broadcast
    memcpy(bytes+ETH_ALEN, dest_mac, ETH_ALEN);
    // move sender to target, again
    memmove(bytes+ARP_START+0x12, bytes+ARP_START+0x8, ETH_ALEN+4); 
    // fill in sender
    memcpy(bytes+ARP_START+0x8, dest_mac, ETH_ALEN);
    *(uint32_t*)(bytes+ARP_START+0x8+ETH_ALEN) = dest_ip;
    // make this response
    bytes[ARP_START+0x7] = 0x02;

    // clean up response
    memset(bytes+ARP_START+0x1c,0,18);

    // we need to send 64b to get FCS right
    if (send(fd, bytes, plen, 0) < 64) {
        perror("send_arp");
    }
    if (debuglevel) {
      printf("Sent %lu arp bytes\n", plen);
      bin2hex(bytes, plen);
    }
}

/**
 * process_and_send_arp(int fd, u_char *bytes, size_t plen)
 *
 * responsible for sending IP-SLA and RPM responses for UDP
 *
 * @param fd - File descriptor to send response to
 * @param bytes - Received bytes and working area
 * @param plen - Length of received packet
 */
void process_and_send_udp(int fd, u_char *bytes, size_t plen) {
   // received time stamp
   uint32_t recv;
   // timespec for various purposes
   struct timespec res;
   // for swapping sport<->dport
   uint16_t tmp;

   if (debuglevel) {
     printf("Received %lu bytes\n", plen);
     bin2hex(bytes, plen);
   }

   swapmac(bytes);
   swapip(bytes);

   // check for cisco ipsla handshake packet
   if (*(uint16_t*)(bytes+UDP_DPORT) == 0xaf07  && plen > 23) { // port 1967
      // this is probably cisco ipsla.
      if (*(uint8_t*)(bytes+UDP_DATA) == 0x01 &&                // version = 1
          *(uint32_t*)(bytes+UDP_DATA+0x10) == dest_ip &&         // target ip = our IP 
          *(uint16_t*)(bytes+UDP_DATA+0x14) == dest_udp_ip_sla) { // target port = our preselected port
         // truncate packet
         *(uint16_t*)(bytes+IP_O_TOT_LEN) = 0x3400; // htons(52) 
         *(uint16_t*)(bytes+UDP_LEN) = 0x2000; //  htons(32)
         plen = UDP_DATA+24;

         // change to something 8 zeros
         bytes[UDP_DATA+0x3] = 0x08;
         memset(bytes+UDP_DATA+0x4, 0, 8); 
      } else {
         return; // ignore this
      }
   // juniper RPM uses port 7 for udp-ping
   } else if (*(uint16_t*)(bytes+UDP_DPORT) == 0x0700) {  // htons(7)
      if (*(uint16_t*)(bytes+UDP_DATA+0x1c) == 0x0100 &&   // rpm signature
          *(uint16_t*)(bytes+UDP_DATA+0x1e) == 0x1096 && plen > 90) {
         uint32_t usec;
         // get time
         clock_gettime(CLOCK_REALTIME, &res);
         // convert into ms from midnight
         recv = get_ts_utc(&res);
         // put it in place, twice...
         *(uint32_t*)(bytes+UDP_DATA+0x4) = recv;
         *(uint32_t*)(bytes+UDP_DATA+0x8) = recv;
         // fill in little magic (dunno what this is for...)
         memcpy(bytes+UDP_DATA+0x14, "\xee\xdd\xcc\xbb\xaa\xcc\xdd\xee", 8);
         // juniper uses uptime as epoch, we use something similar
         clock_gettime(CLOCK_MONOTONIC, &res); 
         // put in us accurate "uptime"
         *(uint32_t*)(bytes+UDP_DATA+0x24) = htonl(res.tv_sec);
         *(uint32_t*)(bytes+UDP_DATA+0x28) = htonl(res.tv_nsec/1000);
      }
   // cisco IP SLA again.
   } else if (*(uint16_t*)(bytes+UDP_DPORT) == dest_udp_ip_sla && plen > UDP_DATA + 31) {
      clock_gettime(CLOCK_REALTIME, &res);
      if (bytes[UDP_DATA+0x1] == 0x02) {
        // fill in ms accurate time from midnight, aka ICMP timestamp
        *(uint32_t*)(bytes + UDP_DATA + 0x8) = htonl(get_ts_utc(&res));
        // copy packet sequence number
        *(uint16_t*)(bytes + UDP_DATA + 0x0e) = *(uint16_t*)(bytes + UDP_DATA + 0x0c);
      } else if (bytes[UDP_DATA+0x1] == 0x03) {
         uint32_t t2, t3;
         // generate received ntp timestamp
         ts_to_ntp(&res0, &t2, &t3);
         // put it in place
         *(uint32_t*)(bytes+UDP_DATA+0xc) = t2;
         *(uint32_t*)(bytes+UDP_DATA+0x10) = t3;
         // generate about-to-send ntp timestamp
         ts_to_ntp(&res, &t2, &t3);
         // put it in place
         *(uint32_t*)(bytes+UDP_DATA+0x14) = t2;
         *(uint32_t*)(bytes+UDP_DATA+0x18) = t3;
         // copy packet sequence number
         *(uint16_t*)(bytes+UDP_DATA+0x36) = *(uint16_t*)(bytes+UDP_DATA+0x34);
         // fill out some cisco specific cruft
         memcpy(bytes+0x52, "\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x00", 11);
      } else {
         return; 
      }
   } else {
      return; // do not process
   }

   // swap ports round
   tmp = *(uint16_t*)(bytes+UDP_DPORT);
   *(uint16_t*)(bytes+UDP_DPORT) = *(uint16_t*)(bytes+UDP_SPORT);
   *(uint16_t*)(bytes+UDP_SPORT) = tmp;

   // recalculate IP checksum
   *(uint16_t*)(bytes+IP_O_CHKSUM)=0;
   ip_checksum(bytes+IP_START, 20, (uint16_t*)(bytes+IP_O_CHKSUM));

   // recalculate UDP checksum (no offloading for us)
   *(uint16_t*)(bytes+UDP_CHECKSUM) = 0;
   tcp_checksum(bytes+IP_O_SADDR, bytes+IP_O_DADDR, bytes+UDP_START, ntohs(*(uint16_t*)(bytes+UDP_LEN)), (uint16_t*)(bytes+UDP_CHECKSUM));
   if (*(uint16_t*)(bytes+UDP_CHECKSUM) == 0) 
     *(uint16_t*)(bytes+UDP_CHECKSUM) = 0xffff; 

   // ship it out
   if (send(fd, bytes, plen, 0) < (ssize_t)plen) {
     perror("send_udp");
   }
   if (debuglevel) {
      printf("Sent %lu udp bytes\n", plen);
      bin2hex(bytes, plen);
   }
}

/**
 * process_and_send_arp(int fd, u_char *bytes, size_t plen)
 *
 * responsible for sending RPM responses via ICMP
 *
 * @param fd - File descriptor to send response to
 * @param bytes - Received bytes and working area
 * @param plen - Length of received packet
 */
void process_and_send_icmp(int fd, u_char *bytes, size_t plen) {
   uint32_t tmp,recv;
   struct timespec res;
  
   recv = get_ts_utc(&res0);

   if (debuglevel) {
     printf("Received %lu bytes\n", plen);
     bin2hex(bytes, plen);
   }

   swapmac(bytes);
   swapip(bytes);

   // check for ICMP type
   if (*(uint16_t*)(bytes+ICMP_START) == 8) { // icmp echo
     // this is simple ping, change it to response.
     *(uint32_t*)(bytes+ICMP_START) = 0;
   } else if (*(uint16_t*)(bytes+ICMP_START) == 0x000d && plen > 90 &&
       *(uint16_t*)(bytes+ICMP_DATA+0x1c) == 0x0100 &&
       *(uint16_t*)(bytes+ICMP_DATA+0x1e) == 0x1096) {
      // this is a juniper RPM format. we need to put here the recv/trans stamp too
      uint32_t usec,sent;
      // fill in received timestamp
      *(uint32_t*)(bytes+ICMP_DATA+0x4) = recv;
      // juniper uses uptime as epoch, we use something similar
      clock_gettime(CLOCK_MONOTONIC, &res); 
      // put it in place
      *(uint32_t*)(bytes+ICMP_DATA+0x24) = htonl(res.tv_sec);
      *(uint32_t*)(bytes+ICMP_DATA+0x28) = htonl(res.tv_nsec/1000);
      // add transmit ts
      clock_gettime(CLOCK_REALTIME, &res);
      sent = get_ts_utc(&res);
      *(uint32_t*)(bytes+ICMP_DATA+0x08) = sent;
      // change to response
      bytes[ICMP_START] = 0x0e;
   } else {
      return; // do not process
   }

   // recalculate checksums
   *(uint16_t*)(bytes+IP_O_CHKSUM)=0;
   *(uint16_t*)(bytes+ICMP_START+2)=0;
   ip_checksum(bytes+IP_START, 20, (uint16_t*)(bytes+IP_O_CHKSUM));
   ip_checksum(bytes+ICMP_START, plen - ICMP_START, (uint16_t*)(bytes+ICMP_START+2));
   // send packet
   if (send(fd, bytes, plen, 0) < (ssize_t)plen) {
      perror("send_icmp");
   }
   if (debuglevel) {
      printf("Sent %lu icmp bytes\n", plen);
      bin2hex(bytes, plen);
   }
}

/**
 * pak_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes)
 * 
 * handles pcap packets and dispatches them into handlers
 *
 * @param user - opaque data (fd in this case) 
 * @param h - pcap header
 * @param bytes - received bytes
 */
void pak_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes)
{
   u_char response[ETH_FRAME_LEN+1]; // to avoid possible buffer overrun in tcp_checksum
   int fd;
   size_t plen;

   // received timestamp
   clock_gettime(CLOCK_REALTIME, &res0);

   // file descriptor for output
   fd = *(int*)user;

   // check if this is intended for us in the first place
   if (memcmp(bytes, dest_mac, ETH_ALEN) && memcmp(bytes, "\xff\xff\xff\xff\xff\xff", ETH_ALEN)) {
        if (debuglevel) 
           printf("Ignoring pak not intended for us (mac mismatch and not broadcast)\n");
	return;
   }

#ifdef HAS_VLAN
   // require vlan
   if (*(unsigned short*)(bytes+ETH_O_PROTO) != 0x0081) { 
        if (debuglevel)
           printf("Ignoring pak because it has no VLAN and VLAN is required\n");
	return;
   }
#endif

   // choose protocol 
   switch((*(unsigned short*)(bytes+ETH_O_PROTO+ETH_O_VLAN))) {
     case 0x0008:
       // total size of entire packet including everything
       plen = ntohs(*(unsigned short*)(bytes+IP_O_TOT_LEN))+ETH_HLEN+4; 

       if (plen > ETH_FRAME_LEN) return; // accept only 1500 byte packages
       memcpy(response,bytes,plen);

       // ensure dst ip is correct
       if (*(uint32_t*)(response+IP_O_DADDR) != dest_ip) return;

       // choose protocol
       switch(bytes[IP_O_PROTO]) {
         case 0x1:
            // it's icmp.
            process_and_send_icmp(fd,response,plen);
            break;
          case 0x11:
            // udp
            process_and_send_udp(fd,response,plen);
            break;
          default:
            if (debuglevel) {
                 printf("Cannot understand protocol %u\n", bytes[IP_O_PROTO]);
            }
       }
       break;
     // ARP protocol
     case 0x0608:
      // ensure request size.
      if (h->caplen < 46 || h->caplen > ETH_FRAME_LEN) return; // require 45 byte packet
      memcpy(response,bytes,h->caplen);
      process_and_send_arp(fd,response,h->caplen);
      break;
     default:
       if (debuglevel) {
         printf("Cannot understand ethernet protocol %04x\n", *(unsigned short*)(bytes+ETH_O_PROTO+ETH_O_VLAN));
       }
   }
}
