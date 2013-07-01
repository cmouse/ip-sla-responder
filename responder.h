#ifndef _RESPONDER_H
#define _RESPONDER_H 1

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

struct config_s {
   unsigned char mac[ETH_ALEN]; /* our mac address */
   int vlan;                    /* VLAN number, 0 = no vlan support wanted */
   struct in_addr ip_addr;      /* our IPv4 address */
   struct in6_addr ip6_addr;    /* our IPv6 address */
   size_t iflen;
   char *ifnames;               /* names of interface to use */
};

inline uint32_t get_ts_utc(struct timespec *res);
inline void ts_to_ntp(const struct timespec *res, uint32_t *ntp_sec, uint32_t *ntp_fsec);
void bin2hex(const unsigned char *data, size_t dlen);
inline uint16_t ip_checksum(const void *vdata, size_t dlen, uint16_t *target);
inline uint16_t tcp_checksum(const u_char *src_addr, const u_char *dest_addr, u_char *buff, size_t dlen, uint16_t *target);
inline void swapmac(u_char *bytes);
inline void swapip(u_char *bytes);

/*
void process_and_send_arp(int fd, u_char *bytes, size_t plen);
void process_and_send_udp(int fd, u_char *bytes, size_t plen);
void process_and_send_icmp(int fd, u_char *bytes, size_t plen);
void pak_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes);

extern uint32_t dest_ip;
extern uint16_t dest_udp_ip_sla;
extern u_char dest_mac[ETH_ALEN];
extern int debuglevel;
*/

// NEW API
int process_ether(u_char *buffer, size_t length, int *af, const struct config_s *config);

#endif
