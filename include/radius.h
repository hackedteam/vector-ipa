
/* $Id: radius.h 1149 2009-11-17 09:53:46Z alor $ */

#ifndef __RADIUS_H
#define __RADIUS_H

/*
 *    0                   1                   2                   3
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |     Code      |   Identifier  |            Length             |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   | . . . . . . . . . . 16-Bytes Authenticator. . . . . . . . . . |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   | . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . |
 *   | . . . . . . . . . . . . . Attributes  . . . . . . . . . . . . |
 *   | . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

struct radius_header {
   u_int8  code;              /* type of the packet */
      #define RADIUS_ACCESS_REQUEST    0x1
      #define RADIUS_ACCESS_ACCEPT     0x2
      #define RADIUS_ACCESS_REJECT     0x3
      #define RADIUS_ACCOUNT_REQUEST   0x4
      #define RADIUS_ACCOUNT_RESPONSE  0x5
   u_int8  id;                /* identifier */
   u_int16 length;            /* packet length */
   u_int8  auth[16];          /* authenticator */
};

#define RADIUS_HEADER_LEN   0x14  /* 12 bytes */

#define RADIUS_ATTR_USER_NAME             0x01
#define RADIUS_ATTR_NAS_IP_ADDRESS        0x04
#define RADIUS_ATTR_NAS_PORT              0x05
#define RADIUS_ATTR_FRAMED_IP_ADDRESS     0x08
#define RADIUS_ATTR_CALLBACK_NUMBER       0x13
#define RADIUS_ATTR_CALLBACK_ID           0x14
#define RADIUS_ATTR_CALLED_STATION_ID     0x1E
#define RADIUS_ATTR_CALLING_STATION_ID    0x1F
#define RADIUS_ATTR_NAS_ID                0x20
#define RADIUS_ATTR_ACCT_INPUT_OCTETS     0x2A
#define RADIUS_ATTR_ACCT_OUTPUT_OCTETS    0x2B
#define RADIUS_ATTR_ACCT_SESSION_ID       0x2C
#define RADIUS_ATTR_ACCT_STATUS_TYPE      0x28
   #define RADIUS_ACCT_STATUS_START          0x01
   #define RADIUS_ACCT_STATUS_UPDATE         0x03
   #define RADIUS_ACCT_STATUS_STOP           0x02
#define RADIUS_ATTR_ACCT_TERMINATE_CAUSE  0x31
#define RADIUS_ATTR_NAS_PORT_ID           0x57


#define RADIUS_END_USER_REQUEST        1
#define RADIUS_END_LOST_CARRIER        2
#define RADIUS_END_LOST_SERVICE        3
#define RADIUS_END_IDLE_TIMEOUT        4
#define RADIUS_END_SESSION_TIMEOUT     5
#define RADIUS_END_ADMIN_RESET         6
#define RADIUS_END_ADMIN_REBOOT        7
#define RADIUS_END_PORT_ERROR          8
#define RADIUS_END_NAS_ERROR           9
#define RADIUS_END_NAS_REQUEST         10
#define RADIUS_END_NAS_REBOOT          11
#define RADIUS_END_PORT_UNNEEDED       12
#define RADIUS_END_PORT_PREEMPTED      13
#define RADIUS_END_PORT_SUSPENDED      14
#define RADIUS_END_SERVICE_UNAVAILABLE 15
#define RADIUS_END_CALLBACK            16
#define RADIUS_END_USER_ERROR          17
#define RADIUS_END_HOST_REQUEST        18


/* exported functions */

u_char * radius_get_attribute(u_int8 attr, u_int16 *attr_len, u_char *begin, u_char *end);

struct radius_attribute {
   char *name;
   char *value;   /* already decoded */
};

struct radius_attribute * radius_get_next_attribute(u_char **begin, const u_char *end);


#endif

/* EOF */

// vim:ts=3:expandtab


