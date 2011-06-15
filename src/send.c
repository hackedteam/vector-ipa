/*
    MODULE -- Send packets thru libnet

    Copyright (C) Alberto Ornaghi

    $Id: send.c 2851 2010-09-10 09:55:31Z alor $
*/

#include <main.h>
#include <packet.h>
#include <send.h>

#include <libnet.h>

/* globals */

/* protos */

void send_init(void);
static void send_close(void);
int send_get_iface_addr(struct ip_addr *addr);

int send_to_L2(struct packet_object *po);
int send_dns_reply(u_int16 dport, struct ip_addr *sip, struct ip_addr *tip, u_int16 id, u_int8 *data, size_t datalen, u_int16 addi_rr);
int send_tcp(struct ip_addr *sip, struct ip_addr *tip, u_int16 sport, u_int16 dport, u_int32 seq, u_int32 ack, u_int8 flags, u_char *data, size_t len);


/*******************************************/

/*
 * set up the lnet struct to have a socket to send packets
 */

void send_init(void)
{
   libnet_t *l;
   libnet_t *l3;
   char lnet_errbuf[LIBNET_ERRBUF_SIZE];

   /* avoid double initialization */
   if (GBL_LNET->lnet != NULL) {
      DEBUG_MSG(D_DEBUG, "send_init already initialized on %s", GBL_OPTIONS->Riface);
      return;
   }

   if (!GBL_OPTIONS->read && GBL_OPTIONS->Riface == NULL && GBL_CONF->response_iface == NULL) {
      ERROR_MSG("You must specify a RESPONSE interface");
   }

   /* if the iface is not set on command line, get it form the file */
   if (GBL_CONF->response_iface && GBL_OPTIONS->Riface == NULL)
      GBL_OPTIONS->Riface = GBL_CONF->response_iface;

   if (!GBL_OPTIONS->read)
      USER_MSG("Sending to %s...\n", GBL_OPTIONS->Riface);

   /* check when to not initialize libnet */
   if (GBL_OPTIONS->read) {
      DEBUG_MSG(D_INFO, "send_init: skipping... (reading offline)");
      return;
   }

   DEBUG_MSG(D_INFO, "send_init %s", GBL_OPTIONS->Riface);

   /* open the socket at layer 3 */
   l3 = libnet_init(LIBNET_RAW4_ADV, GBL_OPTIONS->Riface, lnet_errbuf);
   ON_ERROR(l3, NULL, "send_init: libnet_init(LIBNET_RAW4_ADV) failed: %s", lnet_errbuf);

   /* open the socket at layer 2 ( GBL_OPTIONS->iface doesn't matter ) */
   l = libnet_init(LIBNET_LINK_ADV, GBL_OPTIONS->Riface, lnet_errbuf);
   ON_ERROR(l, NULL, "send_init: libnet_init(LIBNET_LINK_ADV) failed: %s", lnet_errbuf);

   GBL_LNET->lnet_L3 = l3;
   GBL_LNET->lnet = l;

   atexit(send_close);
}


static void send_close(void)
{
   libnet_destroy(GBL_LNET->lnet);
   libnet_destroy(GBL_LNET->lnet_L3);

   DEBUG_MSG(D_INFO, "ATEXIT: send_closed");
}


int send_get_iface_addr(struct ip_addr *addr)
{
   u_long ip;

   DEBUG_MSG(D_DEBUG, "send_get_iface_addr: %s", GBL_CONF->sniffing_iface);

   /* dont touch the interface reading from file */
   if (!GBL_LNET->lnet || GBL_OPTIONS->read) {
      DEBUG_MSG(D_DEBUG, "send_get_iface_addr: skipping... (not initialized)");
      return -ENOADDRESS;
   }

   /* get the ip address */
   ip = libnet_get_ipaddr4(GBL_LNET->lnet);

    /* if ip is equal to -1 there was an error */
    if (ip != (u_long)~0) {

       /* save the ip address */
       ip_addr_init(addr, AF_INET, (u_char *)&ip);

       return ESUCCESS;
    }

   return -EINVALID;
}

/*
 * send the packet at layer 2
 * this can be used to send ARP messages
 */

int send_to_L2(struct packet_object *po)
{
   libnet_ptag_t t;
   int c;

   /* if not lnet warn the developer ;) */
   if (GBL_LNET->lnet_L3 == 0) {
      DEBUG_MSG(D_ERROR, "send_to_L2: lnet not initialized");
      return 0;
   }

   t = libnet_build_data(po->packet, po->len, GBL_LNET->lnet, 0);
   ON_ERROR(t, -1, "libnet_build_data: %s", libnet_geterror(GBL_LNET->lnet));

   if ((c = libnet_write(GBL_LNET->lnet)) == -1)
      DEBUG_MSG(D_ERROR, "ERROR: libnet_write %d (%d): %s", po->len, c, libnet_geterror(GBL_LNET->lnet));

   /* clear the pblock */
   libnet_clear_packet(GBL_LNET->lnet);

   return c;
}

/*
 * send a dns reply
 */
int send_dns_reply(u_int16 dport, struct ip_addr *sip, struct ip_addr *tip, u_int16 id, u_int8 *data, size_t datalen, u_int16 addi_rr)
{
   libnet_ptag_t t;
   int c;

   /* if not lnet warn the developer ;) */
   if (GBL_LNET->lnet_L3 == 0) {
      DEBUG_MSG(D_ERROR, "send_dns_reply: lnet not initialized");
      return 0;
   }

   /* create the dns packet */
    t = libnet_build_dnsv4(
             LIBNET_UDP_DNSV4_H,    /* TCP or UDP */
             id,                    /* id */
             0x8400,                /* standard reply, no error */
             1,                     /* num_q */
             1,                     /* num_anws_rr */
             0,                     /* num_auth_rr */
             addi_rr,               /* num_addi_rr */
             data,
             datalen,
             GBL_LNET->lnet_L3,     /* libnet handle */
             0);                    /* libnet id */
   ON_ERROR(t, -1, "libnet_build_dns: %s", libnet_geterror(GBL_LNET->lnet_L3));

   /* create the udp header */
   t = libnet_build_udp(
            53,                                             /* source port */
            htons(dport),                                   /* destination port */
            LIBNET_UDP_H + LIBNET_UDP_DNSV4_H + datalen,    /* packet size */
            0,                                              /* checksum */
            NULL,                                           /* payload */
            0,                                              /* payload size */
            GBL_LNET->lnet_L3,                              /* libnet handle */
            0);                                             /* libnet id */
   ON_ERROR(t, -1, "libnet_build_udp: %s", libnet_geterror(GBL_LNET->lnet_L3));

   /* auto calculate the checksum */
   libnet_toggle_checksum(GBL_LNET->lnet_L3, t, LIBNET_ON);

   /* create the IP header */
   t = libnet_build_ipv4(
           LIBNET_IPV4_H + LIBNET_UDP_H + LIBNET_UDP_DNSV4_H + datalen, /* length */
           0,                                                           /* TOS */
           htons(RCS_MAGIC_16),                                         /* IP ID */
           0,                                                           /* IP Frag */
           64,                                                          /* TTL */
           IPPROTO_UDP,                                                 /* protocol */
           0,                                                           /* checksum */
           ip_addr_to_int32(&sip->addr),                                /* source IP */
           ip_addr_to_int32(&tip->addr),                                /* destination IP */
           NULL,                                                        /* payload */
           0,                                                           /* payload size */
           GBL_LNET->lnet_L3,                                           /* libnet handle */
           0);
   ON_ERROR(t, -1, "libnet_build_ipv4: %s", libnet_geterror(GBL_LNET->lnet_L3));

   /* auto calculate the checksum */
   libnet_toggle_checksum(GBL_LNET->lnet_L3, t, LIBNET_ON);

   /* send the packet to Layer 3 */
   if ((c = libnet_write(GBL_LNET->lnet_L3)) == -1)
      DEBUG_MSG(D_ERROR, "ERROR: libnet_write (%d): %s", c, libnet_geterror(GBL_LNET->lnet_L3));

   /* clear the pblock */
   libnet_clear_packet(GBL_LNET->lnet_L3);

   return c;
}

/*
 * send a tcp packet
 */
int send_tcp(struct ip_addr *sip, struct ip_addr *tip, u_int16 sport, u_int16 dport, u_int32 seq, u_int32 ack, u_int8 flags, u_char *data, size_t len)
{
   libnet_ptag_t t;
   int c;

   /* if not lnet warn the developer ;) */
   if (GBL_LNET->lnet_L3 == 0) {
      DEBUG_MSG(D_ERROR, "send_tcp: lnet not initialized");
      return 0;
   }

    t = libnet_build_tcp(
        ntohs(sport),            /* source port */
        ntohs(dport),            /* destination port */
        ntohl(seq),              /* sequence number */
        ntohl(ack),              /* acknowledgement num */
        flags,                   /* control flags */
        32767,                   /* window size */
        0,                       /* checksum */
        0,                       /* urgent pointer */
        LIBNET_TCP_H + len,      /* TCP packet size */
	     data,                    /* payload */
        len,                     /* payload size */
        GBL_LNET->lnet_L3,       /* libnet handle */
        0);                                        /* libnet id */
   ON_ERROR(t, -1, "libnet_build_tcp: %s", libnet_geterror(GBL_LNET->lnet_L3));

   /* auto calculate the checksum */
   libnet_toggle_checksum(GBL_LNET->lnet_L3, t, LIBNET_ON);

   /* create the IP header */
   t = libnet_build_ipv4(
           LIBNET_IPV4_H + LIBNET_TCP_H + len, /* length */
           0,                                  /* TOS */
           htons(RCS_MAGIC_16),                /* IP ID */
           0,                                  /* IP Frag */
           64,                                 /* TTL */
           IPPROTO_TCP,                        /* protocol */
           0,                                  /* checksum */
           ip_addr_to_int32(&sip->addr),       /* source IP */
           ip_addr_to_int32(&tip->addr),       /* destination IP */
           NULL,                               /* payload */
           0,                                  /* payload size */
           GBL_LNET->lnet_L3,                  /* libnet handle */
           0);
   ON_ERROR(t, -1, "libnet_build_ipv4: %s", libnet_geterror(GBL_LNET->lnet_L3));

   /* auto calculate the checksum */
   libnet_toggle_checksum(GBL_LNET->lnet_L3, t, LIBNET_ON);

   /* send the packet to Layer 3 */
   if ((c = libnet_write(GBL_LNET->lnet_L3)) == -1)
      DEBUG_MSG(D_ERROR, "ERROR: libnet_write (%d): %s", c, libnet_geterror(GBL_LNET->lnet_L3));

   /* clear the pblock */
   libnet_clear_packet(GBL_LNET->lnet_L3);

   return c;
}


/* EOF */

// vim:ts=3:expandtab

