/*
    MODULE -- Module to match an user based on radius packets

    Copyright (C) Alberto Ornaghi

    $Id: match_users_radius.c 2653 2010-07-06 07:31:19Z alor $
*/

#include <main.h>
#include <hook.h>
#include <packet.h>
#include <match.h>
#include <match_users.h>
#include <radius.h>

/* global vars */

struct radius_target {
   u_int16 flags;
      #define RT_USER_NAME       0x0001
      #define RT_ACCT_SESS_ID    0x0002
      #define RT_NAS_IP_ADDR     0x0004
      #define RT_NAS_PORT        0x0008
      #define RT_NAS_PORT_ID     0x0010
      #define RT_NAS_ID          0x0020
      #define RT_CALLBACK_NUMBER 0x0040
      #define RT_CALLBACK_ID     0x0080
      #define RT_CALLING_STATION 0x0100
      #define RT_CALLED_STATION  0x0200
   u_char *user_name;
   u_int16 user_name_len;
   u_char *acct_sess_id;
   u_int16 acct_sess_id_len;
   u_char *nas_ip_addr;
   u_int16 nas_ip_addr_len;
   u_char *nas_port;
   u_int16 nas_port_len;
   u_char *nas_port_id;
   u_int16 nas_port_id_len;
   u_char *nas_id;
   u_int16 nas_id_len;
   u_char *callback_number;
   u_int16 callback_number_len;
   u_char *callback_id;
   u_int16 callback_id_len;
   u_char *calling_station_id;
   u_int16 calling_station_id_len;
   u_char *called_station_id;
   u_int16 called_station_id_len;
};

struct radius_node {
   char tag[MAX_TAG_LEN];
   struct radius_target rt;
   LIST_ENTRY (radius_node) next;
};

static LIST_HEAD(, radius_node) radius_root;
static pthread_mutex_t radius_mutex = PTHREAD_MUTEX_INITIALIZER;

/* proto */

void match_user_radius_add(char *value, char *tag, int type);
void match_user_radius_clear(void);
void dissector_radius(struct packet_object *po);
char * rp_inspector_match_target(u_char *begin, u_char *end);
int rp_inspector_match_parameter(u_char *param, u_int16 param_len, u_char *tparam, u_int16 tparam_len);

/*******************************************/

void match_user_radius_add(char *value, char *tag, int type)
{
   struct radius_node *e;
   char *p;

   /*
    * remove the hook. we must do this because we are called on every reload list.
    * otherwise the hook will be setup multiple time
    */
   hook_del(HOOK_PACKET_UDP, dissector_radius);

   /* add the hook on UDP packet, this will pass us all the RADIUS packets to look into */
   hook_add(HOOK_PACKET_UDP, dissector_radius);

   /* create the element for the list */
   SAFE_CALLOC(e, 1, sizeof(struct radius_node));

   snprintf(e->tag, MAX_TAG_LEN-1, "%s", tag);

   /* parse the target specification */
   switch(type) {
      case RADIUS_LOGIN:
         e->rt.flags = RT_USER_NAME;
         e->rt.user_name = (u_char *)strdup(value);
         e->rt.user_name_len = 0;
         break;
      case RADIUS_CALLID:
         e->rt.flags = RT_CALLING_STATION;
         e->rt.calling_station_id = (u_char *)strdup(value);
         e->rt.calling_station_id_len = 0;
         break;
      case RADIUS_TECHKEY:
         /* the Technical Key is the NAS_IP + NAS_PORT */
         e->rt.flags = RT_NAS_IP_ADDR | RT_NAS_PORT_ID;
         if ((p = strchr(value, ':')) != NULL) {
            *p = 0;
            e->rt.nas_ip_addr = (u_char *)strdup(value);
            e->rt.nas_port_id = (u_char *)strdup(p+1);
         } else {
            DEBUG_MSG(D_ERROR, "match_user_radius_add: bad parsing [%s]", value);
            SAFE_FREE(e);
            return;
         }
         break;
      case RADIUS_SESSID:
         e->rt.flags = RT_ACCT_SESS_ID;
         e->rt.acct_sess_id = (u_char *)strdup(value);
         e->rt.acct_sess_id_len = 0;
         break;
   }

   pthread_mutex_lock(&radius_mutex);
   LIST_INSERT_HEAD(&radius_root, e, next);
   pthread_mutex_unlock(&radius_mutex);
}


void match_user_radius_clear(void)
{
   struct radius_node *e, *tmp;

   pthread_mutex_lock(&radius_mutex);

   /* remove all the elements */
   LIST_FOREACH_SAFE(e, &radius_root, next, tmp) {
      SAFE_FREE(e->rt.user_name);
      SAFE_FREE(e->rt.calling_station_id);
      SAFE_FREE(e->rt.acct_sess_id);
      SAFE_FREE(e->rt.nas_ip_addr);
      SAFE_FREE(e->rt.nas_port_id);
      LIST_REMOVE(e, next);
      SAFE_FREE(e);
   }

   pthread_mutex_unlock(&radius_mutex);
}


void dissector_radius(struct packet_object *po)
{
   struct radius_header *radius;
   u_char *data = po->DATA.data;
   u_char *end = po->DATA.data + po->DATA.len;
   u_char *attributes;
   u_char *ptr;
   char *tagp;
   char tag[MAX_TAG_LEN];
   u_int16 ptr_len;
   u_int32 acct_status;
   struct ip_addr framed_ip_addr;
   char tmp[MAX_IP_ADDR_LEN];
   struct timeval tv;

   /* packet is not radius */
   if (ntohs(po->L4.src) != 1645 && ntohs(po->L4.dst) != 1645 &&
       ntohs(po->L4.src) != 1646 && ntohs(po->L4.dst) != 1646 &&
       ntohs(po->L4.src) != 1812 && ntohs(po->L4.dst) != 1812 &&
       ntohs(po->L4.src) != 1813 && ntohs(po->L4.dst) != 1813 )
      return;

   /* sanity check */
   if (po->DATA.len < sizeof(struct radius_header))
      return;

   DEBUG_MSG(D_VERBOSE, "dissector_radius");

   /* parse the packet as a radius header */
   radius = (struct radius_header *)data;

   /* get the pointer to the attributes list */
   attributes = (u_char *)(radius + 1);

   /* we are interested only in ACCOUNTING REQUESTS */
   if (radius->code != RADIUS_ACCOUNT_REQUEST)
      return;

   /* match the target with our specification */
   if ((tagp = rp_inspector_match_target(attributes, end)) == NULL) {
      return;
   }

   snprintf(tag, MAX_TAG_LEN-1, "%s", tagp);

   /* get the status of the accounting request */
   if ((ptr = radius_get_attribute(RADIUS_ATTR_ACCT_STATUS_TYPE, &ptr_len, attributes, end)) == NULL) {
      return;
   }

   /* convert the pointer to an integer */
   acct_status = pntol(ptr);

   /* get the framed ip address */
   ptr = radius_get_attribute(RADIUS_ATTR_FRAMED_IP_ADDRESS, &ptr_len, attributes, end);

   /* save the framed_ip_addr THIS IS THE VALUE WE NEED !! */
   if (ptr && ptr_len > 0) {
      ip_addr_init(&framed_ip_addr, AF_INET, ptr);
   } else {
      return;
   }


   /* add or remove the target to the active target list */
   switch(acct_status) {
      case RADIUS_ACCT_STATUS_START:
      case RADIUS_ACCT_STATUS_UPDATE:
         DEBUG_MSG(D_INFO, "RADIUS TARGET DISCOVERED: [%s] address [%s]", tag, ip_addr_ntoa(&framed_ip_addr, tmp));
         gettimeofday(&tv, NULL);
         active_user_add(&framed_ip_addr, NULL, tag, tv);
         break;

      case RADIUS_ACCT_STATUS_STOP:
         DEBUG_MSG(D_INFO, "RADIUS TARGET DISAPPEARED: [%s] address [%s]", tag, ip_addr_ntoa(&framed_ip_addr, tmp));
         active_user_del(&framed_ip_addr);
         break;
   }

}

char * rp_inspector_match_target(u_char *begin, u_char *end)
{
   struct radius_target attr;
   struct radius_node *e;
   int matches = 0;

   /* parse the packet and extract all the attributes for later matching */
   attr.user_name          = radius_get_attribute(RADIUS_ATTR_USER_NAME, &attr.user_name_len, begin, end);
   attr.acct_sess_id       = radius_get_attribute(RADIUS_ATTR_ACCT_SESSION_ID, &attr.acct_sess_id_len, begin, end);
   attr.nas_ip_addr        = radius_get_attribute(RADIUS_ATTR_NAS_IP_ADDRESS, &attr.nas_ip_addr_len, begin, end);
   attr.nas_port           = radius_get_attribute(RADIUS_ATTR_NAS_PORT, &attr.nas_port_len, begin, end);
   attr.nas_port_id        = radius_get_attribute(RADIUS_ATTR_NAS_PORT_ID, &attr.nas_port_id_len, begin, end);
   attr.nas_id             = radius_get_attribute(RADIUS_ATTR_NAS_ID, &attr.nas_id_len, begin, end);
   attr.callback_number    = radius_get_attribute(RADIUS_ATTR_CALLBACK_NUMBER, &attr.callback_number_len, begin, end);
   attr.callback_id        = radius_get_attribute(RADIUS_ATTR_CALLBACK_ID, &attr.callback_id_len, begin, end);
   attr.calling_station_id = radius_get_attribute(RADIUS_ATTR_CALLING_STATION_ID, &attr.calling_station_id_len, begin, end);
   attr.called_station_id  = radius_get_attribute(RADIUS_ATTR_CALLED_STATION_ID, &attr.called_station_id_len, begin, end);

   pthread_mutex_lock(&radius_mutex);
   /*
    * search if the packet matches a target.
    * all the parameters ar in logic AND
    */
   LIST_FOREACH(e, &radius_root, next) {

      matches = 0;

      if (e->rt.flags & RT_USER_NAME) {
         /* match the parameter */
         if ((matches = rp_inspector_match_parameter(attr.user_name,
                           attr.user_name_len, e->rt.user_name, e->rt.user_name_len)) == 0) {
            continue;
         }
      }

      if (e->rt.flags & RT_ACCT_SESS_ID) {
         /* match the parameter */
         if ((matches = rp_inspector_match_parameter(attr.acct_sess_id,
                           attr.acct_sess_id_len, e->rt.acct_sess_id, e->rt.acct_sess_id_len)) == 0) {
            continue;
         }
      }

      if (e->rt.flags & RT_NAS_IP_ADDR) {
         /* match the parameter */
         if ((matches = rp_inspector_match_parameter(attr.nas_ip_addr,
                           attr.nas_ip_addr_len, e->rt.nas_ip_addr, e->rt.nas_ip_addr_len)) == 0) {
            continue;
         }
      }

      if (e->rt.flags & RT_NAS_PORT) {
         /* match the parameter */
         if ((matches = rp_inspector_match_parameter(attr.nas_port,
                           attr.nas_port_len, e->rt.nas_port, e->rt.nas_port_len)) == 0) {
            continue;
         }
      }

      if (e->rt.flags & RT_NAS_PORT_ID) {
         /* match the parameter */
         if ((matches = rp_inspector_match_parameter(attr.nas_port_id,
                           attr.nas_port_id_len, e->rt.nas_port_id, e->rt.nas_port_id_len)) == 0) {
            continue;
         }
      }

      if (e->rt.flags & RT_NAS_ID) {
         /* match the parameter */
         if ((matches = rp_inspector_match_parameter(attr.nas_id,
                           attr.nas_id_len, e->rt.nas_id, e->rt.nas_id_len)) == 0) {
            continue;
         }
      }

      if (e->rt.flags & RT_CALLBACK_NUMBER) {
         /* match the parameter */
         if ((matches = rp_inspector_match_parameter(attr.callback_number,
                           attr.callback_number_len, e->rt.callback_number, e->rt.callback_number_len)) == 0) {
            continue;
         }
      }

      if (e->rt.flags & RT_CALLBACK_ID) {
         /* match the parameter */
         if ((matches = rp_inspector_match_parameter(attr.callback_id,
                           attr.callback_id_len, e->rt.callback_id, e->rt.callback_id_len)) == 0) {
            continue;
         }
      }

      if (e->rt.flags & RT_CALLING_STATION) {
         /* match the parameter */
         if ((matches = rp_inspector_match_parameter(attr.calling_station_id,
                           attr.calling_station_id_len, e->rt.calling_station_id, e->rt.calling_station_id_len)) == 0) {
            continue;
         }
      }

      if (e->rt.flags & RT_CALLED_STATION) {
         /* match the parameter */
         if ((matches = rp_inspector_match_parameter(attr.called_station_id,
                           attr.called_station_id_len, e->rt.called_station_id, e->rt.called_station_id_len)) == 0) {
            continue;
         }
      }

      /* we have found our target */
      if (matches) {
         pthread_mutex_unlock(&radius_mutex);
         DEBUG_MSG(D_INFO, "RADIUS TARGET: [%s]", e->tag);
         return e->tag;
      }
   }

   pthread_mutex_unlock(&radius_mutex);

   return NULL;
}


int rp_inspector_match_parameter(u_char *param, u_int16 param_len, u_char *tparam, u_int16 tparam_len)
{
   /* if the attribute was not found in the packet or the length differs */
   if (param == NULL || (tparam_len != 0 && param_len != tparam_len))
      return 0;

   /* len = 0 is a special case for string matching with wildcard */
   if (tparam_len == 0) {
      char *txt;
      SAFE_CALLOC(txt, param_len + 1, sizeof(char));
      memcpy(txt, param, param_len);
      if (match_pattern(txt, (char *)tparam)) {
         SAFE_FREE(txt);
         return 1;
      }
      SAFE_FREE(txt);
   } else {
      if (!memcmp(param, tparam, tparam_len))
         return 1;
   }

   return 0;
}



/* EOF */

// vim:ts=3:expandtab

