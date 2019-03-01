#ifndef SNTP_H
#define SNTP_H

#define NTP_BASETIME 2208988800.0
#define NTP_FLOAT_DENOM 4294967296.0
#define USEC_PER_SEC 1000000ULL
#define NTP_PER_SEC  4294967296.0
#define BEIJINGTIME  28800

struct sntp {
  int li;
  int vn;
  int mode;
  int stratum;
  int poll;
  char precision;
  double root_delay;
  double root_dispersion;
  unsigned char identifier[4];
  double reference;
  double originate;
  double receive;
  double transmit;
};

#define SNTP_HEADER_SIZE    48
#define SNTP_MOD_NULL       0
#define SNTP_MOD_ACT        1
#define SNTP_MOD_PAS        2
#define SNTP_MOD_CLIENT     3
#define SNTP_MOD_SERVER     4
#define SNTP_MOD_BDC        5
#define SNTP_MOD_RESERVE    6
#define SNTP_MOD_NOUSE      7

void sntp_pack(unsigned char *, const struct sntp *);
void sntp_unpack(struct sntp *, const unsigned char *);
void sntp_tstotv(double, struct timeval *);
double sntp_tvtots(struct timeval *,int delta);
double sntp_now(int delta);
void hton(unsigned char *buf, unsigned int val);
unsigned int ntoh(const unsigned char *buf);
void pack_ts(unsigned char *buf, double ts);
double unpack_ts(const unsigned char *buf);
#endif
