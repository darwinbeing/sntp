#include <stdio.h>
#include <string.h>
#include <math.h>
#include <sys/time.h>
#include <unistd.h>
#include <time.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sched.h>
#include <errno.h>

#include "sntp.h"

static int  g_udpClientSocket = -1;
static int  g_udpServerSocket = -1;
static int  g_delayUs = 0;
static char *g_ipAddress = "203.107.6.88";
static int  g_udpPort = 123;
static char m_cLeapFalg;
static struct sntp g_sntp;
static double t4 = 0;

static pthread_t g_sntp_client_task_id;
static pthread_t g_sntp_server_task_id;

void hton(unsigned char *buf, unsigned int val)
{
  *(uint32_t *)buf = htonl((uint32_t)val);
}

unsigned int ntoh(const unsigned char *buf)
{
  return ntohl(*(uint32_t *)buf);
}

void pack_ts(unsigned char *buf, double ts)
{
  double i, f;

  f = modf(ts, &i);

  *(uint32_t *)buf = htonl((uint32_t)i);
  *(uint32_t *)(buf + 4) = htonl((uint32_t)(f * NTP_FLOAT_DENOM));
}

double unpack_ts(const unsigned char *buf)
{
  double i, f;
  i = ntohl(*(uint32_t *)buf);
  f = ntohl(*(uint32_t *)(buf + 4)) / NTP_FLOAT_DENOM;
  return (i + f);
}

void sntp_pack(unsigned char *buf, const struct sntp *sntp)
{
  buf[0] = (sntp->li << 6) | (sntp->vn << 3) | sntp->mode;
  buf[1] = sntp->stratum;
  buf[2] = sntp->poll;
  buf[3] = (char)sntp->precision;
  hton(&buf[4], sntp->root_delay * 65536.0);
  hton(&buf[8], sntp->root_dispersion * 65536.0);
  memcpy(&buf[12], &sntp->identifier, 4);
  pack_ts(&buf[16], sntp->reference);
  pack_ts(&buf[24], sntp->originate);
  pack_ts(&buf[32], sntp->receive);
  pack_ts(&buf[40], sntp->transmit);
}

void sntp_unpack(struct sntp *sntp, const unsigned char *buf)
{
  sntp->li = buf[0] >> 6;
  sntp->vn = (buf[0] >> 3) & 0x07;
  sntp->mode = buf[0] & 0x07;
  sntp->stratum = buf[1];
  sntp->poll = buf[2];
  sntp->precision = buf[3];
  sntp->root_delay = ntoh(&buf[4]) / 65536.0;
  sntp->root_dispersion = ntoh(&buf[8]) / 65536.0;
  memcpy(&sntp->identifier, &buf[12], 4);
  sntp->reference = unpack_ts(&buf[16]);
  sntp->originate = unpack_ts(&buf[24]);
  sntp->receive = unpack_ts(&buf[32]);
  sntp->transmit = unpack_ts(&buf[40]);
}

void sntp_tstotv(double ts, struct timeval *tv)
{
  double i, f;

  f = modf(ts - NTP_BASETIME, &i);
  /* tv->tv_sec = i + BEIJINGTIME; */
  tv->tv_sec = i;
  tv->tv_usec = f * 1e6;
}

double sntp_tvtots(struct timeval *tv, int delta)
{
  uint64_t tmp_usec = tv->tv_usec + USEC_PER_SEC + delta;
  uint64_t sec_carry = (tmp_usec / USEC_PER_SEC) - 1;
  tv->tv_usec = tmp_usec % USEC_PER_SEC;
  tv->tv_sec += sec_carry;
  return NTP_BASETIME + tv->tv_sec + tv->tv_usec * 1e-6;
}

double sntp_now(int delta)
{
  struct timeval now;
  gettimeofday(&now, NULL);
  return sntp_tvtots(&now,delta+30*2);
}

/* Prints a timeval in a human readable format */
void print_tv(struct timeval tv) {
  time_t nowtime;
  struct tm *nowtm;
  char tmbuf[64], buf[64];

  nowtime = tv.tv_sec;
  nowtm = localtime(&nowtime);
  strftime(tmbuf, sizeof (tmbuf), "%Y-%m-%d %H:%M:%S", nowtm);

  snprintf(buf, sizeof buf, "%s.%06d", tmbuf, (int) tv.tv_usec);
  printf("%s\n", buf);
}

typedef struct _value_string {
  uint32_t      value;
  char *strptr;
}value_string;

static const value_string li_types[] =
{
  {0, "no warning" },
  {1, "last minute of the day has 61 seconds" },
  {2, "last minute of the day has 59 seconds" },
  {3, "unknown (clock unsynchronized)" },
  {0, NULL}
};

static const value_string ver_nums[] =
{
  {0,"reserved" },
  {1,"NTP Version 1" },
  {2,"NTP Version 2" },
  {3,"NTP Version 3" },
  {4,"NTP Version 4" },
  {5,"reserved" },
  {6,"reserved" },
  {7,"reserved" },
  {0,NULL}

};

static const value_string mode_types[] = {
  { 0, "reserved" },
  { 1, "symmetric active" },
  { 2, "symmetric passive" },
  { 3, "client" },
  { 4, "server" },
  { 5, "broadcast" },
  { 6, "reserved for NTP control message"},
  { 7, "reserved for private use" },
  { 0, NULL}
};

static const char *val2str(int val, const value_string *vs)
{
  int i = 0;

  if(vs) {
    while (vs[i].strptr) {
      if (vs[i].value == val) {
        return(vs[i].strptr);
      }
      i++;
    }
  }

  return NULL;
}

void print_ntp_packet(const struct sntp *p) {

  struct timeval tv;

  printf("\nLeap Indicator: %s\n", val2str(p->li, li_types));
  printf("Version number: %s\n", val2str(p->vn, ver_nums));
  printf("Mode: %s\n", val2str(p->mode, mode_types));

  sntp_tstotv(p->originate, &tv);
  printf("Origin Timestamp   (T1): ");
  print_tv(tv);

  sntp_tstotv(p->receive, &tv);
  printf("Receive Timestamp  (T2): ");
  print_tv(tv);

  sntp_tstotv(p->transmit, &tv);
  printf("Transmit Timestamp (T3): ");
  print_tv(tv);

  sntp_tstotv(t4, &tv);
  printf("Current Timestamp  (T4): ");
  print_tv(tv);

}

int sntp_client_init()
{
  int sockopt_on = 1;
  struct sockaddr_in sockaddr;
  g_udpClientSocket = socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP);
  if (g_udpClientSocket < 0) {
    return -1;
  }

  memset(&sockaddr, 0, sizeof(sockaddr));
  sockaddr.sin_family = AF_INET;
  sockaddr.sin_port = htons(g_udpPort);
  /* sockaddr.sin_addr.s_addr = htonl(INADDR_ANY); */
  sockaddr.sin_addr.s_addr = inet_addr(g_ipAddress);

  if(setsockopt(g_udpClientSocket, SOL_SOCKET, SO_REUSEADDR, (char *) &sockopt_on,sizeof(int)) < 0) {
    return -2;
  }

  /* int enable = 1; */
  /* if(setsockopt(g_udpClientSocket,SOL_SOCKET,SO_TIMESTAMP,&enable,sizeof(enable))<0) { */
  /*   return -3; */
  /* } */

  struct timeval tv;
  tv.tv_sec = 3;
  tv.tv_usec = 0;
  if(setsockopt(g_udpClientSocket, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof(tv)) < 0) {
    return -4;
  }

  tv.tv_sec = 3;
  tv.tv_usec = 0;
  if(setsockopt(g_udpClientSocket, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv)) < 0) {
    return -4;
  }

  return 0;
}

int sntp_server_init()
{
  int sockopt_on = 1;
  struct sockaddr_in sockaddr;
  g_udpServerSocket = socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP);
  if (g_udpServerSocket < 0) {
    return -1;
  }

  memset(&sockaddr, 0, sizeof(sockaddr));
  sockaddr.sin_family = AF_INET;
  sockaddr.sin_port = htons(g_udpPort);
  sockaddr.sin_addr.s_addr = htonl(INADDR_ANY);

  setsockopt(g_udpServerSocket, SOL_SOCKET, SO_REUSEADDR, (char *) &sockopt_on,sizeof(int));
  if (bind(g_udpServerSocket,(struct sockaddr*)&sockaddr,sizeof(sockaddr)) <0 ) {
    return -2;
  }

  int enable = 1;
  if (setsockopt(g_udpServerSocket,SOL_SOCKET,SO_TIMESTAMP,&enable,sizeof(enable))<0) {
    return -3;
  }

  return 0;
}

int sntp_receive_packet(int netsock, char *pbuf, int buflen, struct sockaddr_in *fromAddr, struct timeval *tv)
{
  int ret = -1;
  struct msghdr msg;
  struct cmsghdr *cmsg;
  struct iovec iov;
  struct sockaddr_in from_addr;
  char ctrl[CMSG_SPACE(sizeof(struct timeval))];

  memset(&msg, 0, sizeof(msg));
  memset(&from_addr, 0, sizeof(from_addr));
  memset(&ctrl, 0, sizeof(ctrl));

  iov.iov_base= pbuf;
  iov.iov_len = buflen;

  msg.msg_name = &from_addr;
  msg.msg_namelen = sizeof(from_addr);

  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  msg.msg_control = (caddr_t)ctrl;
  msg.msg_controllen = sizeof(ctrl);

  ret = recvmsg(netsock, &msg, 0);
  if (ret <= 0)
    return ret;

  *fromAddr = from_addr;
  for (cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL; cmsg = CMSG_NXTHDR(&msg, cmsg)){
    if ((cmsg->cmsg_level == SOL_SOCKET) && (cmsg->cmsg_type == SO_TIMESTAMP)){
      memcpy(tv, (struct timeval *)CMSG_DATA(cmsg), sizeof(struct timeval));
      break;
    }
  }

  /* gettimeofday(&tv, NULL); */

  return ret;
}

int sntp_send_packet(int netsock,char *pbuf, int buflen, struct sockaddr_in *fromAddr)
{
  int ret=0;
  struct msghdr msg;
  struct iovec iov;
  union {
    struct cmsghdr cm;
    char control[CMSG_SPACE(sizeof(struct timeval))];
  } control_un;
  struct cmsghdr *pcmsg;

  struct sockaddr_in to_addr;
  memset(&to_addr, 0, sizeof(to_addr));
  to_addr.sin_port = fromAddr->sin_port;
  to_addr.sin_family = AF_INET;
  to_addr.sin_addr.s_addr = fromAddr->sin_addr.s_addr;

  msg.msg_name = &to_addr;
  msg.msg_namelen = sizeof(struct sockaddr_in);
  iov.iov_base = pbuf;
  iov.iov_len = buflen;
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  msg.msg_control = control_un.control;
  msg.msg_controllen = sizeof(control_un.control);

  struct timeval ktv;
  pcmsg = CMSG_FIRSTHDR(&msg);
  pcmsg->cmsg_len = CMSG_LEN(sizeof(struct timeval));
  pcmsg->cmsg_level = SOL_SOCKET;
  pcmsg->cmsg_type = SCM_RIGHTS;
  *((struct timeval *)CMSG_DATA(pcmsg)) =ktv;

  ret = sendmsg(netsock, &msg, 0);
  return ret;
}

int sntp_client(int s, char *ipAddress, struct sntp *sntp)
{
  int ret = -1;
  unsigned char buf[SNTP_HEADER_SIZE];
  struct sockaddr ss;
  socklen_t size = sizeof(ss);
  struct sockaddr_in dstAddr;
  struct timeval tv;
  /*
    Timestamp Name          ID   When Generated
    ------------------------------------------------------------
    Originate Timestamp     T1   time request sent by client
    Receive Timestamp       T2   time request received by server
    Transmit Timestamp      T3   time reply sent by server
    Destination Timestamp   T4   time reply received by client
    The roundtrip delay d and local clock offset t are defined as follows:
    delay = (T4 - T1) - (T3 - T2)   offset = ((T2 - T1) + (T3 - T4)) / 2
  */

  memset(&dstAddr, 0, sizeof(dstAddr));

  dstAddr.sin_port = htons(g_udpPort);
  dstAddr.sin_family = AF_INET;
  dstAddr.sin_addr.s_addr = inet_addr(g_ipAddress);

  memset(sntp, 0, sizeof(*sntp));
  sntp->li = 0;
  sntp->vn = 4;
  sntp->mode = 3;
  sntp->stratum = 0;
  sntp->poll = 0;
  sntp->precision = 0;
  sntp->root_delay = 0.0;
  sntp->root_dispersion = 0.0;

  strncpy((char *) sntp->identifier, "TSSM", sizeof(sntp->identifier));
  sntp->reference = 0.0;
  sntp->originate = 0.0;
  sntp->receive = 0.0;
  sntp->transmit = sntp_now(g_delayUs);
  sntp_pack(buf, sntp);

  ret = sntp_send_packet(s, (char*)buf, sizeof(buf), &dstAddr);
  if(ret <= 0) {
    return -1;
  }

  ret = sntp_receive_packet(s, (char*)buf, sizeof(buf), &dstAddr, &tv);
  if (ret <= 0){
    return -2;
  }

  t4 = sntp_now(g_delayUs);
  sntp_unpack(sntp, buf);

  double t1 = sntp->originate;
  double t2 = sntp->receive;
  double t3 = sntp->transmit;
  double t = ((t2 - t1) + (t3 - t4)) / 2.0;
  double d  = (t4 - t1) - (t3 - t2);

  double i;
  double f;
  struct timeval delta;
  static int firstchecktime = 0;
  struct timeval now;

  if(firstchecktime == 0) {
    firstchecktime = 1;
    sntp_tstotv(t3, &now);
    f = modf(d, &i);
    delta.tv_sec = (long) i;
    delta.tv_usec = (long) (f * 1e6);
    uint64_t usec = (uint64_t)now.tv_sec * 1000000UL + now.tv_usec + (uint64_t)delta.tv_sec * 1000000UL + delta.tv_usec;
    now.tv_sec = (long)(usec / 1000000UL);
    now.tv_usec = (long)(usec % 1000000UL);

    settimeofday(&now, NULL);
  } else {
    f = modf(t, &i);
    delta.tv_sec = (long) i;
    delta.tv_usec = (long) (f * 1e6);

    ret = adjtime(&delta, NULL);
  }

  print_ntp_packet(sntp);
  printf("d=%f(ms) t=%f(ms) t1=%f t2=%f t3=%f t4=%f\n", d * 1000, t * 1000, t1, t2, t3, t4);

  return 0;
}

int sntp_server(int s)
{
  int ret = -1;
  unsigned char buf[SNTP_HEADER_SIZE];
  struct sockaddr ss;
  socklen_t size = sizeof(ss);
  struct sockaddr_in dstAddr;
  struct sntp msg;
  struct timeval tv;
  struct sockaddr_in fromAddr;
  ret = sntp_receive_packet(s, (char*)buf, sizeof(buf), &fromAddr, &tv);
  if (ret <= 0){
    return -1;
  }

  unsigned char oritime[8] = "";
  char identifierName[8] = "";
  memcpy(oritime,(char*)&(buf[40]),8);
  sntp_unpack(&msg, buf);

  memcpy(identifierName, msg.identifier,4);
  /* if (0 != strcmp("TSSM",identifierName)){ */
  /*   return -2; */
  /* } */

  msg.li = 0;
  msg.vn = 4;
  msg.mode = (msg.mode == SNTP_MOD_CLIENT) ? SNTP_MOD_SERVER : SNTP_MOD_PAS;
  msg.stratum = 2;
  msg.poll = 0x06;
  msg.precision = /*-6*/0xec;
  msg.root_delay = 0.0;
  msg.root_dispersion = 0.0;

  /* strncpy((char *) msg.identifier, "TSSM", sizeof(msg.identifier)); */

  msg.originate/*t2*/ = msg.transmit;
  msg.receive  /*t3*/ = NTP_BASETIME + tv.tv_sec+(double)tv.tv_usec/1000000;
  msg.transmit /*t4*/ = sntp_now(g_delayUs);
  msg.reference/*t1*/ = msg.transmit/*t4*/;
  sntp_pack(buf, &msg);

  memcpy(&buf[24],oritime,8);

  ret = sntp_send_packet(s,(char*)buf, sizeof(buf), &fromAddr);
  if(ret <= 0) {
    return -3;
  }

  return 0;
}

static void *sntp_client_main_trampoline(void *arg)
{
  while(1) {
    sntp_client(g_udpClientSocket, g_ipAddress, &g_sntp);
    usleep(5000 * 1000);
  }

  return 0;
}

static void *sntp_server_main_trampoline(void *arg)
{

  struct sched_param sched;
  sched_getparam(0, &sched);
  sched.sched_priority = sched_get_priority_max(SCHED_RR);
  sched_setscheduler(0, SCHED_RR, &sched);

  while(1) {
    sntp_server(g_udpServerSocket);
  }

  return 0;
}

int main(int argc, char *argv[])
{
  int ret;

  sntp_client_init();

  ret = pthread_create(&g_sntp_client_task_id, NULL, sntp_client_main_trampoline, NULL);
  if (ret < 0) {
    exit(-1);
  }

  sntp_server_init();
  ret = pthread_create(&g_sntp_server_task_id, NULL, sntp_server_main_trampoline, NULL);
  if (ret < 0) {
    exit(-2);
  }

  pthread_join(g_sntp_client_task_id, NULL);
  pthread_join(g_sntp_server_task_id, NULL);

  return 0;
}
