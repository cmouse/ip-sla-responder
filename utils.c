#include "responder.h"

static const unsigned long NTP_EPOCH = 2208988800UL;
static const unsigned long NTP_SCALE_FRAC = 4294967296UL;

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

