
/* $Id: netconf.h 2547 2010-06-22 14:29:28Z alor $ */

#ifndef __NETCONF_H
#define __NETCONF_H

#define MAX_PATH 260

typedef struct _RncProto {
   u_int  code;
   u_int  size;
} RncProtoHeader;

#define RNC_SIGN_LEN 32
typedef struct _RncProtoLogin {
   char sign[RNC_SIGN_LEN];
} RncProtoLogin;

typedef struct _RncProtoVersion {
   char version[16];
} RncProtoVersion;

typedef struct _RncProtoMonitor {
   char status[16];
   u_int disk;
   u_int cpu;
   u_int pcpu;
   char desc[1024];
} RncProtoMonitor;

typedef struct _RncProtoConfig {
   char filename[MAX_PATH];
   u_int size;
} RncProtoConfig;

/* under MACOS the tm struct has two additional fields, use this instead */
struct mytm {
   int   tm_sec;     /* seconds after the minute [0-60] */
   int   tm_min;     /* minutes after the hour [0-59] */
   int   tm_hour;    /* hours since midnight [0-23] */
   int   tm_mday;    /* day of the month [1-31] */
   int   tm_mon;     /* months since January [0-11] */
   int   tm_year;    /* years since 1900 */
   int   tm_wday;    /* days since Sunday [0-6] */
   int   tm_yday;    /* days since January 1 [0-365] */
   int   tm_isdst;   /* Daylight Savings Time flag */
};

#define RNC_MAX_LOG_LEN 1024
typedef struct _RncProtoLog {
   struct mytm timestamp;
   u_int type;
      #define RNC_LOG_INFO  0x00
      #define RNC_LOG_ERROR 0x01
      #define RNC_LOG_DEBUG 0x02
   char desc[RNC_MAX_LOG_LEN];
} RncProtoLog;

#define RNC_PROTO_INVALID  0x000F0000  // Non usare
#define RNC_PROTO_OK       0x000F0001  // OK
#define RNC_PROTO_NO       0x000F0002  // Comando fallito o non e' stato possibile eseguirlo
#define RNC_PROTO_BYE      0x000F0003  // Chiusura di connessione
#define RNC_PROTO_LOGIN    0x000F0004  // Login del componente verso il sistema
#define RNC_PROTO_MONITOR  0x000F0005  // Informazioni sullo stato del componente
#define RNC_PROTO_CONF     0x000F0006  // Chiede se c'e' una nuova configurazione
#define RNC_PROTO_LOG      0x000F0007  // Invia log
#define RNC_PROTO_VERSION  0x000F0008  // Invia la versione del componente

/* protos */
extern void netconf_start(void);

#endif

/* EOF */

// vim:ts=3:expandtab

