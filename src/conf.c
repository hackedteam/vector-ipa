/*
    MODULE -- configuration manipulation module

    Copyright (C) Alberto Ornaghi

    $Id: conf.c 3422 2011-02-09 12:55:25Z alor $
*/

#include <main.h>
#include <conf.h>
#include <file.h>
#include <match.h>
#include <timer.h>
#include <encryption.h>

/* globals */


static struct conf_entry common[] = {
   { "log_level", NULL },
   { "sniffing_iface", NULL },
   { "sniffing_iface_channel", NULL },
   { "response_iface", NULL },
   { "pcap_filter", NULL },
   { NULL, NULL },
};

static struct conf_entry rules[] = {
   { "redirected_fqdn", NULL },
   { "redirected_url", NULL },
   { "redirected_users", NULL },
   { "intercepted_files", NULL },
   { NULL, NULL },
};

static struct conf_entry netconf[] = {
   { "rnc_sign_file", NULL },
   { "rnc_port", NULL },
   { NULL, NULL },
};

static struct conf_entry wifi[] = {
   { "wifi_key", NULL },
   { NULL, NULL },
};

static struct conf_entry targets[] = {
   { "user_timeout", NULL },
   { NULL, NULL },
};

static struct conf_section sections[] = {
   { "COMMON", (struct conf_entry *)&common},
   { "NETCONF", (struct conf_entry *)&netconf},
   { "TARGETS", (struct conf_entry *)&targets},
   { "WIFI", (struct conf_entry *)&wifi},
   { "RULES", (struct conf_entry *)&rules},
   { NULL, NULL },
};

/* protos */

void load_conf(void);
static void reload_lists(void);
static void init_structures(void);
static void set_pointer(struct conf_entry *entry, char *name, void *ptr);

static struct conf_entry * search_section(char *title);
static void * search_entry(struct conf_entry *section, char *name);

/************************************************/

/*
 * since GBL_CONF is in the heap, it is not constant
 * so we have to initialize it here and not in the
 * structure definition
 */

static void init_structures(void)
{
   int i = 0, j = 0;

   DEBUG_MSG(D_DEBUG, "init_structures");

   set_pointer((struct conf_entry *)&common, "log_level", &GBL_CONF->log_level);
   set_pointer((struct conf_entry *)&common, "sniffing_iface", &GBL_CONF->sniffing_iface);
   set_pointer((struct conf_entry *)&common, "sniffing_iface_channel", &GBL_CONF->sniffing_iface_channel);
   set_pointer((struct conf_entry *)&common, "response_iface", &GBL_CONF->response_iface);
   set_pointer((struct conf_entry *)&common, "pcap_filter", &GBL_PCAP->filter);
   set_pointer((struct conf_entry *)&targets, "user_timeout", &GBL_TARGETS->user_timeout);
   set_pointer((struct conf_entry *)&netconf, "rnc_sign_file", &GBL_NETCONF->rnc_sign_file);
   set_pointer((struct conf_entry *)&netconf, "rnc_port", &GBL_NETCONF->rnc_port);
   set_pointer((struct conf_entry *)&wifi, "wifi_key", &GBL_NET->wifi_key);
   set_pointer((struct conf_entry *)&rules, "redirected_fqdn", &GBL_CONF->redirected_fqdn);
   set_pointer((struct conf_entry *)&rules, "redirected_url", &GBL_CONF->redirected_url);
   set_pointer((struct conf_entry *)&rules, "redirected_users", &GBL_CONF->redirected_users);
   set_pointer((struct conf_entry *)&rules, "intercepted_files", &GBL_CONF->intercepted_files);

   /* sanity check */
   do {
      do {
         if (sections[i].entries[j].value == NULL) {
            DEBUG_MSG(D_ERROR, "INVALID init: %s %s", sections[i].entries[j].name, sections[i].title);
            BUG("check the log file...");
         }
      } while (sections[i].entries[++j].name != NULL);
      j = 0;
   } while (sections[++i].title != NULL);
}

/*
 * associate the pointer to a struct
 */

static void set_pointer(struct conf_entry *entry, char *name, void *ptr)
{
   int i = 0;

   /* search the name */
   do {
      /* found ! set the pointer */
      if (!strcmp(entry[i].name, name))
         entry[i].value = ptr;

   } while (entry[++i].name != NULL);
}

/*
 * load the configuration from rcsredirect.conf file
 */

void load_conf(void)
{
   FILE *fc;
   char line[512];
   char *p, *q, **tmp;
   int lineno = 0, ret;
   struct conf_entry *curr_section = NULL;
   void *value = NULL;
   struct timer_hook th;

   /* initialize the structures */
   init_structures();

   DEBUG_MSG(D_DEBUG, "load_conf");

   /* the user has specified an alternative config file */
   if (GBL_CONF->file) {
      DEBUG_MSG(D_INFO, "load_conf: alternative config: %s", GBL_CONF->file);
      fc = fopen(GBL_CONF->file, FOPEN_READ_TEXT);
      ON_ERROR(fc, NULL, "Cannot open %s", GBL_CONF->file);
   } else {
      /* errors are handled by the function */
      fc = open_data("etc", CONF_FILE, FOPEN_READ_TEXT);
      ON_ERROR(fc, NULL, "Cannot open %s", CONF_FILE);
   }

   /* read the file */
   while (fgets(line, 512, fc) != 0) {

      /* update the line count */
      lineno++;

      /* trim out the comments */
      if ((p = strchr(line, '#')))
         *p = '\0';

      /* trim out the new line */
      if ((p = strchr(line, '\n')))
         *p = '\0';

      q = line;

      /* trim the initial spaces */
      while (q < line + sizeof(line) && *q == ' ')
         q++;

      /* skip empty lines */
      if (line[0] == '\0' || *q == '\0')
         continue;

      /* here starts a new section [...] */
      if (*q == '[') {

         /* remove the square brackets */
         if ((p = strchr(line, ']')))
            *p = '\0';
         else
            FATAL_ERROR("Missing ] in %s line %d", CONF_FILE, lineno);

         p = q + 1;

         DEBUG_MSG(D_INFO, "load_conf: SECTION: %s", p);

         /* get the pointer to the right structure */
         if ( (curr_section = search_section(p)) == NULL) {
            DEBUG_MSG(D_INFO, "load_conf: skipping section %d [%s]", lineno, q);
            //FATAL_ERROR("Invalid section in %s line %d", CONF_FILE, lineno);
            continue;
         }

         /* read the next line */
         continue;
      }

      /* variable outside a section */
      if (curr_section == NULL) {
         DEBUG_MSG(D_INFO, "load_conf: skipping entry outside section %d [%s]", lineno, q);
         //FATAL_ERROR("Entry outside a section in %s line %d", CONF_FILE, lineno);
         continue;
      }

      /* sanity check */
      if (!strchr(q, '='))
         FATAL_ERROR("Parse error %s line %d", CONF_FILE, lineno);

      p = q;

      /* split the entry name from the value */
      do {
         if (*p == ' ' || *p == '='){
            *p = '\0';
            break;
         }
      } while (p++ < line + sizeof(line) );

      /* move p to the value */
      p++;
      do {
         if (*p != ' ' && *p != '=')
            break;
      } while (p++ < line + sizeof(line) );


      if ( (value = search_entry(curr_section, q)) == NULL) {
         DEBUG_MSG(D_INFO, "load_conf: skipping line %d [%s]", lineno, q);
         //FATAL_ERROR("Invalid entry in %s line %d", CONF_FILE, lineno);
         continue;
      }

      /* strings must be handled in a different way */
      if (*p == '\"') {
         /* trim the first quotes */
         p++;

         /* set the string value */
         tmp = (char **)value;
         *tmp = strdup(p);

         /* trim the ending quotes */
         p = *tmp;
         do {
            if (*p == '\"')
               *p = 0;
         } while (p++ < *tmp + strlen(*tmp) );

         DEBUG_MSG(D_INFO, "load_conf: \tENTRY: %s  [%s]", q, *tmp);

      } else {
         /* set the integer value */
         *(int *)value = strtol(p, (char **)NULL, 10);
         DEBUG_MSG(D_INFO, "load_conf: \tENTRY: %s  %d", q, *(int *)value);
      }
   }

   fclose(fc);

   /* open the signature file */
   fc = open_data("etc", GBL_NETCONF->rnc_sign_file, FOPEN_READ_TEXT);
   ON_ERROR(fc, NULL, "Cannot open %s", GBL_NETCONF->rnc_sign_file);

   SAFE_CALLOC(GBL_NETCONF->rnc_sign, RNC_SIGN_LEN + 1, sizeof(char));

   ret = fread(GBL_NETCONF->rnc_sign, RNC_SIGN_LEN, sizeof(char), fc);
   if (ret < 0)
      ERROR_MSG("load_conf: cannot read network signature");

   DEBUG_MSG(D_INFO, "load_conf: network signature is: [%s]", GBL_NETCONF->rnc_sign);

   fclose(fc);

   if (GBL_NET->wifi_key) {
      DEBUG_MSG(D_INFO, "load_conf: wifi key is: [%s]", GBL_NET->wifi_key);

      /* parse the wifi encryption key */
      if (wifi_key_prepare(GBL_NET->wifi_key) != ESUCCESS) {
         DEBUG_MSG(D_ERROR, "load_conf: invalid wifi key [%s]", GBL_NET->wifi_key);
      }
   }

   /*
    * set up the timers for the reload of the files
    * it will be reloaded only if the SIGHUP is received
    */
   th.sec = 1;
   th.func = &reload_lists;
   add_timer(&th);
}

/*
 * load the rules from the files
 */

void load_rules(void)
{
   /* load the files with the lists of sites to be blocked */
   load_fqdn();
   load_url();
   load_users();
   load_request();
}


/*
 * returns the pointer to the struct
 * named "title"
 */
static struct conf_entry * search_section(char *title)
{
   int i = 0;

   do {
      /* the section was found */
      if (!strcasecmp(sections[i].title, title))
         return sections[i].entries;

   } while (sections[++i].title != NULL);

   return NULL;
}

/*
 * returns the pointer to the value
 * named "name" of the sections "section"
 */

static void * search_entry(struct conf_entry *section, char *name)
{
   int i = 0;

   do {
      /* the section was found */
      if (!strcasecmp(section[i].name, name))
         return section[i].value;

   } while (section[++i].name != NULL);

   return NULL;
}

/*
 * reload the lists upon SIG HUP
 */
static void reload_lists(void)
{
   /* not set by the signal handler */
   if (GBL_ENV->reload == 0)
      return;

   GBL_ENV->reload = 0;

   DEBUG_MSG(D_INFO, "reload_lists: reloading the lists...");

   /* load the files with the lists of sites to be blocked */
   load_rules();
}

/* EOF */

// vim:ts=3:expandtab

