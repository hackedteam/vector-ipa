/*
    MODULE -- Module to match an URL

    Copyright (C) Alberto Ornaghi

    $Id: match_url.c 3041 2010-10-26 10:11:18Z daniele $
*/

#include <main.h>
#include <hook.h>
#include <file.h>
#include <send.h>
#include <packet.h>

#include <match.h>
#include <match_url.h>

/* global vars */

static LIST_HEAD(, url_node) url_root;
static pthread_mutex_t root_mutex = PTHREAD_MUTEX_INITIALIZER;

static u_char static_splash_page[SPLASH_PAGE_LEN];
static size_t static_splash_page_len;

/* proto */

static int urllist_load(void);
static int urllist_find(const char *url, const char *tag);
struct url_node *list_new(const char *value);
int list_find(const char *url, const char *tag);
void load_url(void);
void match_url_init(void);
void match_url(struct packet_object *po);
static int prepare_splash_page(char *url, char *splash_page, size_t *splash_page_len);
static void mangle_url(const char *host, const char *page, char *redir_url, size_t len, char *tag);
static int http_redirect(struct packet_object *po, u_char *splash_page, size_t splash_page_len);

/*******************************************/

int urllist_find(const char* url, const char *tag)
{
   int ret;

   pthread_mutex_lock(&root_mutex);
   ret = list_find(url, tag);
   pthread_mutex_unlock(&root_mutex);

   return ret;
}

/*
 * parse a line and save it in the list.
 * the line has this format:
 *   TAG probability url
 */

struct url_node *list_new(const char *value)
{
   struct url_node *tmp;
   char *p, *prob;

   SAFE_CALLOC(tmp, 1, sizeof(struct url_node));

   /* separate the string at the blank space */
   if ((p = strchr(value, ' ')) != NULL)
      *p = 0;
   else
      return NULL;

   snprintf(tmp->tag, MAX_TAG_LEN-1, "%s", value);

   /* point to the probability */
   prob = ++p;

   /* separate the string at the blank space */
   if ((p = strchr(prob, ' ')) != NULL)
      *p = 0;
   else
      return NULL;

   /* convert it to a integer */
   tmp->probability = atoi(prob);

   /*
    * the first match is always true, so set it to true
    * all the subsequent match will use the probability flag
    */
   tmp->first_match = 1;

   /* point to the url*/
   p++;

   snprintf(tmp->url, MAX_URL-1, "%s", p);

   pthread_mutex_lock(&root_mutex);
   LIST_INSERT_HEAD(&url_root, tmp, next);
   pthread_mutex_unlock(&root_mutex);

   return tmp;
}

int list_find(const char *url, const char *tag)
{
   struct url_node *current;
   int prob;

   /* if url is parametrized, ignore it */
   if (strpbrk(url, "?=&"))
      return -ENOTFOUND;

   LIST_FOREACH(current, &url_root, next) {
      /* match the exact tag */
      if (strcmp(current->tag, tag))
         continue;
      /* match the url with wildcards */
      if (match_pattern(url, current->url)) {
         if (current->first_match) {
            DEBUG_MSG(D_INFO, "URL MATCH: [first time] will BE matched [%s]", url);
            /* reset the first_match flag */
            current->first_match = 0;
            return ESUCCESS;
         } else {
            /* calculate the probability of redirection */
            prob = random() % 100;
            if (prob < current->probability) {
               DEBUG_MSG(D_INFO, "URL MATCH: [%d:%d] will BE matched [%s]", prob, current->probability, url);
               return ESUCCESS;
            } else {
               DEBUG_MSG(D_INFO, "URL MATCH: [%d:%d] will NOT be matched [%s]", prob, current->probability, url);
               return -ENOTFOUND;
            }
         }
      }
   }

   return -ENOTFOUND;
}

int urllist_load(void)
{
   FILE *fc, *fb;
   char line[512];
   int counter = 0;
   char *p, *q;

   DEBUG_MSG(D_INFO, "load_url: %s", GBL_CONF->redirected_url);

   ON_ERROR(GBL_CONF->redirected_url, NULL, "Cannot open a NULL file!");

   /* errors are handled by the function */
   fc = open_data("etc", GBL_CONF->redirected_url, FOPEN_READ_TEXT);
   ON_ERROR(fc, NULL, "Cannot open %s", GBL_CONF->redirected_url);

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

      /* special case for the REDIRECT_PAGE */
      if (!strncmp(line, "REDIRECT_PAGE = ", 16)) {
         fb = open_data("etc", line + strlen("REDIRECT_PAGE = "), FOPEN_READ_TEXT);
         ON_ERROR(fb, NULL, "Cannot open %s", line + strlen("REDIRECT_PAGE = "));

         /* load the splash page */
         static_splash_page_len = fread(static_splash_page, 1, sizeof(static_splash_page), fb);

         DEBUG_MSG(D_INFO, "urllist_load: splash_page_len = %d", static_splash_page_len);

         fclose(fb);
         continue;
      }

      /* insert url into the list */
      if (list_new(line) == NULL)
         DEBUG_MSG(D_ERROR, "ERROR: urllist_load: bad parsing of line [%s]", line);

      /* update the line count */
      counter++;
   }

   fclose(fc);

   DEBUG_MSG(D_INFO, "List of redirected URL contains : %04d entries.", counter);

   return 0;
}

void load_url(void)
{
   struct url_node *current, *tmp;

   pthread_mutex_lock(&root_mutex);

   /* free the old list */
   LIST_FOREACH_SAFE(current, &url_root, next, tmp) {
       LIST_REMOVE(current, next);
       SAFE_FREE(current);
   }

   pthread_mutex_unlock(&root_mutex);

   /* load the new URL list */
   urllist_load();

   return;
}


void match_url(struct packet_object *po)
{
   char *tmp, *q;
   char tag[MAX_TAG_LEN + 4];
   char splash_page[SPLASH_PAGE_LEN];
   size_t splash_page_len;
   char host[256];
   char page[512];
   char url[4096];
   char redir_url[4096];

   /* if we are not correctly configured, don't mind if reading from file */
   if (GBL_NET->network_error && !GBL_OPTIONS->read)
      return;

   /* ignore everything from the proxy itself */
   if (!ip_addr_cmp(&po->L3.src, &GBL_NET->proxy_ip) || !ip_addr_cmp(&po->L3.dst, &GBL_NET->proxy_ip))
      return;

   /* ignore packets on ports different from 80 */
   if (po->L4.dst != htons(80))
      return;

   /* if the packet is not interesting (not tagged by the user discovery) */
   if (!strcmp(po->tag, ""))
      return;

   /* prepare the buffers */
   memset(host, 0, sizeof(host));
   memset(page, 0, sizeof(host));

   tmp = (char *)po->DATA.data;

   /* intercept only the request from the client */
   if (!strncasecmp(tmp, "GET ", 4))
      tmp += strlen("GET ");
   else if (!strncasecmp(tmp, "POST ", 5))
      tmp += strlen("POST ");
   else
      return;

   /* check if the the request includes Host: */
   if (!strcasestr(tmp, "Host: "))
      return;

   /* Get the page from the request */
   strncpy(page, tmp, sizeof(page));

   /* The path is relative, search for the Host */
   if ((page[0] == '/') && (q = strcasestr(tmp, "Host: "))) {
      strncpy(host, q + strlen("Host: "), sizeof(host));
      if ((q = strchr(host, '\r')) != NULL)
         *q = 0;
   }

   /* terminate the page */
   if ((q = strcasestr(page, " HTTP")) != NULL)
      *q = 0;

   /* decode the escape chars */
   str_decode_url((u_char *)host);
   str_decode_url((u_char *)page);

   memset(url, 0, sizeof(url));
   snprintf(url, sizeof(url)-1, "%s%s", host, page);

   /* extract the first part of the url */
   snprintf(tag, sizeof(tag)-1, "%s", url);
   if ((q = strchr(tag, '.')) != NULL)
      *q = 0;

   DEBUG_MSG(D_VERBOSE, "URL: [%s][%s]", po->tag, url);

   /*
    * if the tag in the po is equal to the first part of the url
    * it means that we have already redirected it and the browser
    * is performing the second request, so we have to skip it
    * otherwise we will enter an infinite loop of redirection
    */
   if (!strcmp(tag, po->tag)) {
      DEBUG_MSG(D_DEBUG, "URL already REDIRECTED, skipping it");
      return;
   }

   /* search in the list */
   if (urllist_find(url, po->tag) == ESUCCESS) {

      DEBUG_MSG(D_EXCESSIVE, "requested page: %s", po->DATA.data);

      DEBUG_MSG(D_INFO, "URL matched REDIRECTED URL: %s ", url);
      /*
       * calculate the new redirected url and put it in the FQDN list
       * the tag we use here was inserted by the user discovery module
       * into the packet object tag
       */
      mangle_url(host, page, redir_url, sizeof(redir_url), po->tag);
      /* prepare the page */
      if ( prepare_splash_page(redir_url, splash_page, &splash_page_len) == ESUCCESS)
      {
         /* redirect the connection */
         http_redirect(po, (u_char *)splash_page, splash_page_len);

         GBL_STATS->redir_url++;

         DEBUG_MSG(D_EXCESSIVE, "Splash page:\n%s", splash_page);
      } else {
         DEBUG_MSG(D_INFO, "URL too long, not redirected.");
      }
   }
}

void match_url_init(void)
{
   DEBUG_MSG(D_INFO, "match_url_init");

   hook_add(HOOK_PACKET_TCP, &match_url);
}

int prepare_splash_page(char *url, char *splash_page, size_t *splash_page_len)
{
   char *page;
   size_t len;
   char len_str[8];
   char date_str[64];
   struct tm *ttm;
   time_t tt;

   /* zero the splash_page */
   memset(splash_page, 0, SPLASH_PAGE_LEN);

   /* make a copy of the global splash page to be modified */
   SAFE_CALLOC(page, 1, static_splash_page_len + 1);
   strncpy(page, (char *)static_splash_page, static_splash_page_len);

   /* replace the date */
   time(&tt);
   ttm = localtime(&tt);
   strftime(date_str, sizeof(date_str), "%a, %d %b %G %T %z", ttm);
   str_replace(&page, "%DATE%", date_str);

   /* replace the location */
   str_replace(&page, "%LOCATION%", url);

   /* calculate the length of the response */
   len = strlen(page);
   len -= strlen("%LENGTH%");
   if (len > 1000 - 4)
      len += 4; // 4 chars for Content-Length: yyyy
   else if (len > 100 - 3)
      len += 3; // 3 chars for Content-Length: yyy
   else if (len > 10 - 2)
      len += 2; // 3 chars for Content-Length: yy

   /* convert the len to a string */
   snprintf(len_str, sizeof(len_str)-1, "%d", (int)len);

   /* replace the final length of the page */
   str_replace(&page, "%LENGTH%", len_str);

   /* copy it back to the splash page */
   strncpy((char *)splash_page, page, SPLASH_PAGE_LEN);

   DEBUG_MSG(D_DEBUG, "prepare_splash_page: len = %d", len);
   /* set the total len of the page */
   *splash_page_len = len;

   /* don't go over 1024 */
   if (*splash_page_len > SPLASH_PAGE_LEN)
      return -ENOTHANDLED;

   SAFE_FREE(page);

   return ESUCCESS;
}

void mangle_url(const char *host, const char *page, char *redir_url, size_t len, char *tag)
{
   char redir_host[1024];
   struct in_addr dummy;
   char *mhost;

   /* check if the host is an explicit ip address */
   if ( inet_aton(host, &dummy) != 0 ) {
      /* we have to mangle the ip address to resemble an hostname */
      DEBUG_MSG(D_INFO, "IP ADDRESS DETECTED: mangling it...");
      SAFE_STRDUP(mhost, host);
      str_replace(&mhost, ".", "-");
      snprintf(redir_host, 1024, "%s.%s%s%s", tag, IP_IDENT_PREFIX, mhost, IP_IDENT_SUFFIX);
      SAFE_FREE(mhost);
   } else {
      /* simply pre-pend the tag to the hostname */
      snprintf(redir_host, 1024, "%s.%s", tag, host);
   }

   /* prepare the redirect url*/
   snprintf(redir_url, len, "http://%s%s", redir_host, page);

   /* append the new host to the list of FQDN to be redirected */
   fqdn_append(redir_host);

   DEBUG_MSG(D_DEBUG, "host [%s] added to the FQDN list", redir_host);
}


int http_redirect(struct packet_object *po, u_char *splash_page, size_t splash_page_len)
{
   char tmp[MAX_ASCII_ADDR_LEN];
   int c = 0;
   u_int seq, ack;

   /*
    * the packet passed by the conntrack module is the PSH from the client
    * we have the spoof a server reply
    */
   DEBUG_MSG(D_VERBOSE, "http_redirect: REDIRECT [%s] [%u][%u] [%d]", ip_addr_ntoa(&po->L3.dst, tmp), ntohl(po->L4.seq), ntohl(po->L4.ack), po->DATA.len);

   /* send the splash page over a FIN packet */
   seq = ntohl(po->L4.ack);
   ack = ntohl(po->L4.seq) + po->DATA.len;

   c = send_tcp(&po->L3.dst, &po->L3.src, po->L4.dst, po->L4.src, htonl(seq), htonl(ack), TH_FIN|TH_ACK, splash_page, splash_page_len);
   DEBUG_MSG(D_EXCESSIVE, "sent FIN: %d [%u][%u]", c, seq, ack);

   /* send the RST to avoid ACK storm */
   seq = ntohl(po->L4.ack) + static_splash_page_len + 1;
   ack = ntohl(po->L4.seq) + po->DATA.len;

   c = send_tcp(&po->L3.dst, &po->L3.src, po->L4.dst, po->L4.src, htonl(seq), htonl(ack), TH_RST|TH_ACK, NULL, 0);
   DEBUG_MSG(D_EXCESSIVE, "sent RST: %d [%u][%u]", c, seq, ack);

   return 0;
}

/* EOF */

// vim:ts=3:expandtab

