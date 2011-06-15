/*
    MODULE -- decoder module

    Copyright (C) Alberto Ornaghi

    $Id: decode.c 2679 2010-07-14 15:46:43Z alor $
*/

#include <main.h>
#include <decode.h>
#include <threads.h>
#include <ui.h>
#include <packet.h>
#include <hook.h>
#include <capture.h>

#include <pcap/pcap.h>
#include <pthread.h>

/* globals */

static SLIST_HEAD (, dec_entry) protocols_table;

struct dec_entry {
   u_int32 type;
   u_int8 level;
   FUNC_DECODER_PTR(decoder);
   SLIST_ENTRY (dec_entry) next;
};

/* protos */

void __init data_init(void);
FUNC_DECODER(decode_data);

void decode_captured(u_char *param, const struct pcap_pkthdr *pkthdr, const u_char *pkt);
void add_decoder(u_int8 level, u_int32 type, FUNC_DECODER_PTR(decoder));
void del_decoder(u_int8 level, u_int32 type);
void * get_decoder(u_int8 level, u_int32 type);

/*******************************************/

void decode_captured(u_char *param, const struct pcap_pkthdr *pkthdr, const u_char *pkt)
{
   FUNC_DECODER_PTR(packet_decoder);
   struct packet_object po;
   int len;
   u_char *data;
   size_t datalen;

   DEBUG_MSG(D_EXCESSIVE, "CAPTURED: 0x%04x bytes", pkthdr->caplen);

   /* save the timestamp of the last captured packet */
   GBL_STATS->rxtimestamp = pkthdr->ts.tv_sec;
   GBL_STATS->rx++;
   GBL_STATS->bytes += pkthdr->caplen;

   if (GBL_OPTIONS->read)
      /* update the offset pointer */
      GBL_PCAP->dump_off = ftell(pcap_file(GBL_PCAP->pcap));

   /* bad packet */
   if (pkthdr->caplen > UINT16_MAX) {
      return;
   }

   if (GBL_OPTIONS->analyze) {

      data = (u_char *)pkt;
      datalen = pkthdr->caplen;

      /*
       * deal with truncated packets:
       * if someone has created a pcap file with the snaplen
       * too small we have to skip the packet (is not interesting for us)
       */
      if (GBL_PCAP->snaplen <= datalen) {
         USER_MSG("Truncated packet detected, skipping...\n");
         return;
      }

      /* alloc the packet object structure to be passed through decoders */
      packet_create_object(&po, data, datalen);
      /* set the po timestamp */
      memcpy(&po.ts, &pkthdr->ts, sizeof(struct timeval));
#if 0
      /* HOOK POINT: RECEIVED */
      hook_point(HOOK_RECEIVED, &po);
#endif

      /*
       * start the analysis through the decoders stack
       *
       * if the packet can be handled it will reach the top of the stack
       * where the decoder_data will dispatch it to the registered dissectors
       *
       * after this function the packet is completed (all flags set)
       */
      packet_decoder = get_decoder(LINK_LAYER, GBL_PCAP->dlt);
      BUG_IF(packet_decoder == NULL);
      packet_decoder(data, datalen, &len, &po);

#if 0
      /* HOOK POINT: DECODED */
      hook_point(HOOK_DECODED, &po);
#endif

      /* free the structure */
      packet_destroy_object(&po);
   }

   /*
    * if it is the last packet of a pcap file
    * we have to exit the pcap loop
    */
   if (GBL_OPTIONS->read && GBL_PCAP->dump_size == GBL_PCAP->dump_off) {
      capture_stop();
   }

   return;
}


/*
 * add a decoder to the decoders table
 */
void add_decoder(u_int8 level, u_int32 type, FUNC_DECODER_PTR(decoder))
{
   struct dec_entry *e;

   SAFE_CALLOC(e, 1, sizeof(struct dec_entry));

   e->level = level;
   e->type = type;
   e->decoder = decoder;

   /* split into two list to be faster */
   SLIST_INSERT_HEAD(&protocols_table, e, next);

   return;
}

/*
 * get a decoder from the decoders table
 */

void * get_decoder(u_int8 level, u_int32 type)
{
   struct dec_entry *e;
   void *ret;

   SLIST_FOREACH (e, &protocols_table, next) {
      if (e->level == level && e->type == type) {
         ret = (void *)e->decoder;
         return ret;
      }
   }

   return NULL;
}

/*
 * remove a decoder from the decoders table
 */

void del_decoder(u_int8 level, u_int32 type)
{
   struct dec_entry *e;

   SLIST_FOREACH (e, &protocols_table, next) {
      if (e->level == level && e->type == type) {
         SLIST_REMOVE(&protocols_table, e, dec_entry, next);
         SAFE_FREE(e);
         return;
      }
   }

   return;
}

/* EOF */

// vim:ts=3:expandtab

