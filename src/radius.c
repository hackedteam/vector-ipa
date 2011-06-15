/*
    MODULE -- Module for radius parsing

    Copyright (C) Alberto Ornaghi

    $Id: radius.c 1149 2009-11-17 09:53:46Z alor $
*/

#include <main.h>
#include <inet.h>
#include <radius.h>

/* globals */

struct radius_attr_name {
   u_char attr;
   char *name;
   u_char type;
      #define ATTR_STRING  0
      #define ATTR_HEX     1
      #define ATTR_INTEGER 2
      #define ATTR_ADDRESS 3
};

static struct radius_attr_name attr_name_list[] = {
   {   1, "User-Name", ATTR_STRING},
   {   2, "User-Password", ATTR_STRING},
   {   3, "CHAP-Password", ATTR_STRING},
   {   4, "NAS-IP-Address", ATTR_ADDRESS},
   {   5, "NAS-Port", ATTR_INTEGER},
   {   6, "Service-Type", ATTR_INTEGER},
   {   7, "Framed-Protocol", ATTR_INTEGER},
   {   8, "Framed-IP-Address", ATTR_ADDRESS},
   {   9, "Framed-IP-Netmask", ATTR_ADDRESS},
   {  10, "Framed-Routing", ATTR_INTEGER},
   {  11, "Filter-Id", ATTR_HEX},
   {  12, "Framed-MTU", ATTR_INTEGER},
   {  13, "Framed-Compression", ATTR_INTEGER},
   {  14, "Login-IP-Host", ATTR_ADDRESS},
   {  15, "Login-Service", ATTR_INTEGER},
   {  16, "Login-TCP-Port", ATTR_INTEGER},
   /* 17 unused */
   {  18, "Reply-Message", ATTR_STRING},
   {  19, "Callback-Number", ATTR_STRING},
   {  20, "Callback-Id", ATTR_STRING},
   /* 21 unused */
   {  22, "Framed-Route", ATTR_STRING},
   {  23, "Framed-IPX-Network", ATTR_INTEGER},
   {  24, "State", ATTR_STRING},
   {  25, "Class", ATTR_STRING},
   {  26, "Vendor-Specific", ATTR_STRING},
   {  27, "Session-Timeout", ATTR_INTEGER},
   {  28, "Idle-Timeout", ATTR_INTEGER},
   {  29, "Termination-Action", ATTR_INTEGER},
   {  30, "Called-Station-Id", ATTR_STRING},
   {  31, "Calling-Station-Id", ATTR_STRING},
   {  32, "NAS-Identifier", ATTR_STRING},
   {  33, "Proxy-State", ATTR_STRING},
   {  34, "Login-LAT-Service", ATTR_STRING},
   {  35, "Login-LAT-Node", ATTR_STRING},
   {  36, "Login-LAT-Group", ATTR_STRING},
   {  37, "Framed-AppleTalk-Link", ATTR_INTEGER},
   {  38, "Framed-AppleTalk-Network", ATTR_INTEGER},
   {  39, "Framed-AppleTalk-Zone", ATTR_STRING},
   {  40, "Acct-Status-Type", ATTR_INTEGER},
   {  41, "Acct-Delay-Time", ATTR_INTEGER},
   {  42, "Acct-Input-Octets", ATTR_INTEGER},
   {  43, "Acct-Output-Octets", ATTR_INTEGER},
   {  44, "Acct-Session-Id", ATTR_STRING},
   {  45, "Acct-Authentic", ATTR_INTEGER},
   {  46, "Acct-Session-Time", ATTR_INTEGER},
   {  47, "Acct-Input-Packets", ATTR_INTEGER},
   {  48, "Acct-Output-Packets", ATTR_INTEGER},
   {  49, "Acct-Terminate-Cause", ATTR_INTEGER},
   {  50, "Acct-Multi-Session-Id", ATTR_STRING},
   {  51, "Acct-Link-Count", ATTR_INTEGER},
   {  52, "Acct-Input-Gigawords", ATTR_INTEGER},
   {  53, "Acct-Output-Gigawords", ATTR_INTEGER},
   /* 54 unused */
   {  55, "Event-Timestamp", ATTR_INTEGER},
   /* 56-59 unused */
   {  60, "CHAP-Challenge", ATTR_STRING},
   {  61, "NAS-Port-Type", ATTR_INTEGER},
   {  62, "Port-Limit", ATTR_INTEGER},
   {  63, "Login-LAT-Port", ATTR_HEX},
   {  64, "Tunnel-Type", ATTR_INTEGER},
   {  65, "Tunnel-Medium-Type", ATTR_INTEGER},
   {  66, "Tunnel-Client-Endpoint", ATTR_STRING},
   {  67, "Tunnel-Server-Endpoint", ATTR_STRING},
   {  68, "Tunnel-Connection", ATTR_STRING},
   {  69, "Tunnel-Password", ATTR_STRING},
   /* 70-74 ARAP */
   {  75, "Password-Retry", ATTR_INTEGER},
   {  76, "Prompt", ATTR_INTEGER},
   {  77, "Connect-Info", ATTR_STRING},
   {  78, "Configuration-Token", ATTR_STRING},
   {  79, "EAP-Message", ATTR_STRING},
   {  80, "Message-Authenticator", ATTR_STRING},
   {  81, "Tunnel-Private-Group-ID", ATTR_STRING},
   {  82, "Tunnel-Assignment-ID", ATTR_STRING},
   {  83, "Tunnel-Preference", ATTR_INTEGER},
   {  84, "ARAP-Challenge-Response", ATTR_STRING},
   {  85, "Acct-Interim-Interval", ATTR_INTEGER},
   {  86, "Tunnel-Packets Lost", ATTR_INTEGER},
   {  87, "NAS-Port-ID", ATTR_STRING},
   {  88, "Framed-Pool", ATTR_STRING},
   {  90, "Tunnel-Client-Auth-ID", ATTR_STRING},
   {  91, "Tunnel-Server-Auth-ID", ATTR_STRING},
   { 0x0, NULL, 0},
};

/* protos */

u_char * radius_get_attribute(u_int8 attr, u_int16 *attr_len, u_char *begin, u_char *end);
struct radius_attribute * radius_get_next_attribute(u_char **begin, const u_char *end);

/************************************************/

/*
 * find a radius attribute thru the list
 */
u_char * radius_get_attribute(u_int8 attr, u_int16 *attr_len, u_char *begin, u_char *end)
{
   /* the parameter has no lenght until found */
   *attr_len = 0;

   /* sanity check */
   if (begin == NULL || end == NULL)
      return NULL;

   if (begin > end)
      return NULL;

   DEBUG_MSG(D_VERBOSE, "radius_get_attribute: [%d]", attr);

   /* stop when the attribute list ends */
   while (begin < end) {

      /* get the len of the attribute and subtract the header len */
      *attr_len = *(begin + 1) - 2;

      /* we have found our attribute */
      if (*begin == attr) {
         /* return the pointer to the attribute value */
         return begin + 2;
      }

      /* move to the next attribute */
      if (*(begin + 1) > 0) {
         begin += *(begin + 1);
      } else {
         *attr_len = 0;
         return NULL;
      }
   }

   /* not found */
   *attr_len = 0;
   return NULL;
}


struct radius_attribute * radius_get_next_attribute(u_char **begin, const u_char *end)
{
   u_char *param;
   size_t len = 0, i, j;
   struct radius_attribute *ra;
   struct ip_addr ipa;
   char tmp[MAX_ASCII_ADDR_LEN];

   /* sanity check */
   if (*begin == NULL || end == NULL)
      return NULL;

   if (*begin > end)
      return NULL;

   /* get the attribute and the lenght */
   param = *begin;
   len = param[1];

   /* sanity check */
   if (len == 0 || len <= 2)
      return NULL;

   /* don't go beyond the end */
   if (param + len > end)
      return NULL;

   /* move the pointer for the next call */
   *begin = param + len;

   /* adjust the len to the real len of the attribute */
   len -= 2;

   DEBUG_MSG(D_DEBUG, "radius_get_next_attribute: [%d][%d]", param[0], len);

   SAFE_CALLOC(ra, 1, sizeof(struct radius_attribute));

   /* initialize the values */
   ra->name = "Unknown-Attribute";
   ra->value = NULL;

   /* search the attribute in the list */
   for (i = 0; attr_name_list[i].name != NULL; i++) {
      if (attr_name_list[i].attr == param[0]) {
         ra->name = attr_name_list[i].name;
         switch (attr_name_list[i].type) {

            case ATTR_HEX:
               /* hex string takes (len * 2) to store the values */
               SAFE_CALLOC(ra->value, (len + 1) * 2, sizeof(char));
               for (j = 0; j < len; j++)
                  sprintf(ra->value + (j * 2), "%02X", param[2+j]);
               break;

            case ATTR_STRING:
               SAFE_CALLOC(ra->value, len + 1, sizeof(char));
               strncpy(ra->value, (char *)param + 2, len);
               break;

            case ATTR_INTEGER:
               /* sanity check */
               if (len != 4)
                  goto bad;

               SAFE_CALLOC(ra->value, len * 2, sizeof(char));
               snprintf(ra->value, len * 2, "%d", pntol(param + 2));
               break;

            case ATTR_ADDRESS:
               /* sanity check */
               if (len != 4)
                  goto bad;

               ip_addr_init(&ipa, AF_INET, param + 2);
               SAFE_CALLOC(ra->value, 16, sizeof(char));
               snprintf(ra->value, 16, "%s", ip_addr_ntoa(&ipa, tmp));
               break;
         }
         break;
      }
   }

   /* the attribute was not found */
   if (ra->value == NULL) {
      SAFE_CALLOC(ra->value, 10, sizeof(char));
      snprintf(ra->value, 10, "%d - %d", param[0], (int)len);
   }

   return ra;

bad:
   ra->value = strdup("Corrupted");

   return ra;
}

/* EOF */

// vim:ts=3:expandtab

