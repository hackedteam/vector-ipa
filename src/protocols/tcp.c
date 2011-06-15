/*
    MODULE -- TCP decoder module

    Copyright (c) Alberto Ornaghi

    $Id: tcp.c 2657 2010-07-07 07:18:33Z alor $
*/

#include <main.h>
#include <decode.h>

/* globals */

struct tcp_header {
   u_int16  sport;      /* source port */
   u_int16  dport;      /* destination port */
   u_int32  seq;        /* sequence number */
   u_int32  ack;        /* acknowledgement number */
#ifndef WORDS_BIGENDIAN
   u_int8   x2:4;       /* (unused) */
   u_int8   off:4;      /* data offset */
#else
   u_int8   off:4;      /* data offset */
   u_int8   x2:4;       /* (unused) */
#endif
   u_int8   flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PSH  0x08
#define TH_ACK  0x10
#define TH_URG  0x20
   u_int16  win;        /* window */
   u_int16  csum;       /* checksum */
   u_int16  urp;        /* urgent pointer */
};

/* tcp options */
#define TCPOPT_EOL              0
#define TCPOPT_NOP              1
#define TCPOPT_MAXSEG           2
#define TCPOPT_WSCALE           3
#define TCPOPT_SACKOK           4
#define TCPOPT_TIMESTAMP        8


/* protos */

FUNC_DECODER(decode_tcp);
void tcp_init(void);

/*******************************************/

/*
 * this function is the initializer.
 * it adds the entry in the table of registered decoder
 */

void __init tcp_init(void)
{
   add_decoder(PROTO_LAYER, NL_TYPE_TCP, decode_tcp);
}


FUNC_DECODER(decode_tcp)
{
   struct tcp_header *tcp;
   u_char *opt_start, *opt_end;

   DEBUG_MSG(D_EXCESSIVE, "%s", __FUNCTION__);

   tcp = (struct tcp_header *)DECODE_DATA;

   opt_start = (u_char *)(tcp + 1);
   opt_end = (u_char*)( ((int)tcp) + tcp->off * 4 );

   DECODED_LEN = (u_int32)(tcp->off * 4);

   /* source and dest port */
   PACKET->L4.src = tcp->sport;
   PACKET->L4.dst = tcp->dport;

   PACKET->L4.len = DECODED_LEN;
   PACKET->L4.header = (u_char *)DECODE_DATA;

   if (opt_start < opt_end) {
      PACKET->L4.options = opt_start;
      PACKET->L4.optlen = opt_end - opt_start;
   } else {
      PACKET->L4.options = NULL;
      PACKET->L4.optlen = 0;
   }

   /* this is TCP */
   PACKET->L4.proto = NL_TYPE_TCP;

   /* save the flags */
   PACKET->L4.flags = tcp->flags;

   /* save the seq number */
   PACKET->L4.seq = tcp->seq;
   PACKET->L4.ack = tcp->ack;

   /* set up the data pointers */
   PACKET->DATA.data = opt_end;
   if (PACKET->L3.payload_len < (u_int32)DECODED_LEN)
      return NULL;
   PACKET->DATA.len = PACKET->L3.payload_len - DECODED_LEN;
   /* HOOK POINT: HOOK_PACKET_TCP */
   hook_point(HOOK_PACKET_TCP, po);

   return NULL;
}


/* EOF */

// vim:ts=3:expandtab

