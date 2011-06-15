
/* $Id: dhcp.h 1149 2009-11-17 09:53:46Z alor $ */

#ifndef __DHCP_H
#define __DHCP_H

/*
 * RFC: 2131
 *
 *    0                   1                   2                   3
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |     op (1)    |   htype (1)   |   hlen (1)    |   hops (1)    |
 *    +---------------+---------------+---------------+---------------+
 *    |                            xid (4)                            |
 *    +-------------------------------+-------------------------------+
 *    |           secs (2)            |           flags (2)           |
 *    +-------------------------------+-------------------------------+
 *    |                          ciaddr  (4)                          |
 *    +---------------------------------------------------------------+
 *    |                          yiaddr  (4)                          |
 *    +---------------------------------------------------------------+
 *    |                          siaddr  (4)                          |
 *    +---------------------------------------------------------------+
 *    |                          giaddr  (4)                          |
 *    +---------------------------------------------------------------+
 *    |                          chaddr  (16)                         |
 *    +---------------------------------------------------------------+
 *    |                          sname   (64)                         |
 *    +---------------------------------------------------------------+
 *    |                          file    (128)                        |
 *    +---------------------------------------------------------------+
 *    |                       options  (variable)                     |
 *    +---------------------------------------------------------------+
 */

struct dhcp_header {
   u_int8   op;
      #define BOOTREQUEST  1
      #define BOOTREPLY    2
   u_int8   htype;
   u_int8   hlen;
   u_int8   hops;
   u_int32  id;
   u_int16  secs;
   u_int16  flags;
   u_int32  ciaddr;
   u_int32  yiaddr;
   u_int32  siaddr;
   u_int32  giaddr;
   u_int8   chaddr[16];
   u_int8   sname[64];
   u_int8   file[128];
   u_int32  magic;
};

/* DHCP options */
enum {
   DHCP_MAGIC_COOKIE    = 0x63825363,
   DHCP_DISCOVER        = 0x01,
   DHCP_OFFER           = 0x02,
   DHCP_REQUEST         = 0x03,
   DHCP_ACK             = 0x05,
   DHCP_OPT_NETMASK     = 0x01,
   DHCP_OPT_ROUTER      = 0x03,
   DHCP_OPT_DNS         = 0x06,
   DHCP_OPT_DOMAIN      = 0x0f,
   DHCP_OPT_RQ_ADDR     = 0x32,
   DHCP_OPT_LEASE_TIME  = 0x33,
   DHCP_OPT_MSG_TYPE    = 0x35,
   DHCP_OPT_SRV_ADDR    = 0x36,
   DHCP_OPT_RENEW_TIME  = 0x3a,
   DHCP_OPT_CLI_IDENT   = 0x3d,
   DHCP_OPT_END         = 0xff,
   DHCP_OPT_MIN_LEN     = 0x12c,
};

/* functions */

extern u_char * dhcp_get_option(u_char opt, u_char *ptr, u_char *end);

#endif

/* EOF */

// vim:ts=3:expandtab


