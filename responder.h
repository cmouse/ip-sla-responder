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
#define ETH_O_VLAN 4

#define IP_MAGIC 0x45

#define IP_START (ETH_HLEN)
#define IP_O_TOS (ip_start+1)
#define IP_O_TOT_LEN (ip_start+2)
#define IP_O_ID (ip_start+4)
#define IP_O_FRAG_OFF (ip_start+6)
#define IP_O_TTL (ip_start+8)
#define IP_O_PROTO (ip_start+9)
#define IP_O_CHKSUM (ip_start+10)
#define IP_O_SADDR (ip_start+12)
#define IP_O_DADDR (ip_start+16)

#define IP6_START (ETH_HLEN)
#define IP6_O_LEN (ip6_start + 4)
#define IP6_O_NH (ip6_start + 6)
#define IP6_O_HL (ip6_start + 7)
#define IP6_O_SADDR (ip6_start + 8)
#define IP6_O_DADDR (ip6_start + 24)

#define ICMP_START (ip_start+20)
#define ICMP_DATA (ICMP_START+8)

#define UDP_START (ip_start+20)
#define UDP_SPORT (UDP_START)
#define UDP_DPORT (UDP_START+2)
#define UDP_LEN (UDP_START+4)
#define UDP_CHECKSUM (UDP_START+6)
#define UDP_DATA (UDP_START+8)

#define UDP6_START (ip6_start + 40)
#define UDP6_O_SRCPORT (UDP6_START)
#define UDP6_O_DSTPORT (UDP6_START + 2)
#define UDP6_O_LEN (UDP6_START + 4)
#define UDP6_O_CHECKSUM (UDP6_START + 6)
#define UDP6_O_DATA (UDP6_START + 8)

#define ARP_START (ETH_HLEN)

struct config_s {
   unsigned char mac[ETH_ALEN]; /* our mac address */
   unsigned char mac6[ETH_ALEN]; /* our multicast v6 mac */
   int vlan;                    /* VLAN number, 0 = no vlan support wanted */
   struct in_addr ip_addr;      /* our IPv4 address */
   struct in6_addr ip6_addr;    /* our IPv6 address */
   struct in6_addr link6_addr;  /* link-local address */
   struct in6_addr mc6_addr;    /* multicast address */
   char ifname[IFNAMSIZ];       /* name of interface to use */
   int debuglevel;              /* 0 = no, 1 = yes, 2 = with dumps */
   struct timespec res0;        /* receive timestamp */ 
   uint16_t cisco_port;         /* Port to listen for Cisco IPSLA */
   size_t plen;                 /* actual length of packet */
   int do_ip4;
   int do_ip6;
};

struct pak_handler_s {
  struct config_s *config;
  int fd;
};

inline uint32_t get_ts_utc(struct timespec *res);
inline void ts_to_ntp(const struct timespec *res, uint32_t *ntp_sec, uint32_t *ntp_fsec);
void bin2hex(const unsigned char *data, size_t dlen);
inline uint16_t ip_checksum(const unsigned char *buffer, size_t dlen, uint16_t *target);
inline uint16_t tcp4_checksum(const u_char *src_addr, const u_char *dest_addr, int proto, u_char *buff, size_t dlen, uint16_t *target);
inline uint16_t tcp6_checksum(const u_char *src_addr, const u_char *dest_addr, int proto, u_char *buff, size_t dlen, uint16_t *target);

inline void swapmac(u_char *bytes);
inline void swapip(u_char *bytes);
void bin2hex(const unsigned char *data, size_t dlen);

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

void pak_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes);
int process_ether(u_char *buffer, size_t length, int *af, struct config_s *config);
int process_arp(u_char *buffer, size_t length, struct config_s *config);
int process_ip(u_char *buffer, size_t length, struct config_s *config);
int process_ip6(u_char *buffer, size_t length, struct config_s *config);
int process_udp4(u_char *buffer, size_t length, struct config_s *config, size_t ip_start);
int process_udp6(u_char *buffer, size_t length, struct config_s *config, size_t ip6_start);
int process_icmp4(u_char *buffer, size_t length, struct config_s *config, size_t ip_start);
int process_icmp6(u_char *buffer, size_t length, struct config_s *config, size_t ip6_start);
int process_cisco4(u_char *buffer, size_t length, struct config_s *config, size_t ip_start);
int process_cisco6(u_char *buffer, size_t length, struct config_s *config, size_t ip6_start);
int process_echo4(u_char *buffer, size_t length, struct config_s *config, size_t ip_start);
int process_echo6(u_char *buffer, size_t length, struct config_s *config, size_t ip_start);

void do_send(int fd, u_char *bytes, size_t plen);
#endif
