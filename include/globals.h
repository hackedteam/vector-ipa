
/* $Id: globals.h 3422 2011-02-09 12:55:25Z alor $ */

#ifndef __GLOBALS_H
#define __GLOBALS_H

#include <inet.h>
#include <ui.h>
#include <encryption.h>
#include <pcap/pcap.h>

/* options form the config  */
struct gbl_conf {
   char *file;
   int log_level;
   char *sniffing_iface;
   int sniffing_iface_channel;
   char *response_iface;
   char *redirected_fqdn;
   char *redirected_url;
   char *redirected_users;
   char *intercepted_files;
};

/* options from getopt */
struct gbl_options {
   char read;
   char analyze;
   char watchdog;
   char *Riface;
   char *Siface;
   int Siface_chan;
   char *pcapfile_in;
};

/* program name and version */
struct program_env {
   char *name;
   char *version;
   char *rcs_version;
   size_t crash;
   char reload;
};

/* rnc parameters */
struct netconf_env {
   char *rnc_sign_file;
   char *rnc_sign;
   int rnc_port;
};

/* targets values */
struct targets_env {
   int user_timeout;
};

/* statistics */
struct stats_env {
   size_t uptime;
   size_t keepalive;
   size_t rxtimestamp;
   u_long rx;
   size_t bytes;
   size_t throughput;
   u_long tot_users;
   u_long active_users;
   u_long redir_fqdn;
   u_long redir_url;
   u_long inf_files;
};

/* pcap structure */
struct pcap_env {
   void     *pcap;         /* this is a pcap_t pointer */
   char     *filter;       /* pcap filter */
   u_int16  snaplen;
   int      dlt;
   u_int32  dump_size;     /* total dump size */
   u_int32  dump_off;      /* current offset */
   struct pcap_stat stats; /* pcap statistics */
};

/* lnet structure */
struct lnet_env {
   void *lnet_L3;       /* this is a libnet_t pointer */
   void *lnet;          /* this is a libnet_t pointer */
};

/* network structure */
struct net_env {
	struct ip_addr proxy_ip;
	char network_error;          /* used when we don't have a PROXY_IP */
	char wireless;               /* if the send interface is wireless */
	u_char wifi_schema;
      #define WIFI_WEP 0x01
      #define WIFI_WPA 0x02
	char *wifi_key;              /* user specified wifi_key */
	u_char wkey[MAX_WKEY_LEN];   /* encoded wifi key, large enough for all encryption schemas */
	size_t wkey_len;
};

/* the globals container */
struct globals {
   struct gbl_conf *conf;
   struct netconf_env *netconf;
   struct gbl_options *options;
   struct ui_ops *ui;
   struct program_env *env;
   struct pcap_env *pcap;
   struct lnet_env *lnet;
   struct stats_env *stats;
   struct net_env *net;
   struct targets_env *targ;
};

struct globals *gbls;

#define GBLS gbls

#define GBL_CONF           (GBLS->conf)
#define GBL_NETCONF        (GBLS->netconf)
#define GBL_OPTIONS        (GBLS->options)
#define GBL_UI             (GBLS->ui)
#define GBL_ENV            (GBLS->env)
#define GBL_PCAP           (GBLS->pcap)
#define GBL_LNET           (GBLS->lnet)
#define GBL_STATS          (GBLS->stats)
#define GBL_NET            (GBLS->net)
#define GBL_TARGETS        (GBLS->targ)

#define GBL_PROGRAM        (GBL_ENV->name)
#define GBL_VERSION        (GBL_ENV->version)
#define GBL_RCS_VERSION    (GBL_ENV->rcs_version)

/* exported functions */

void globals_alloc(void);
void globals_free(void);

#endif

/* EOF */

// vim:ts=3:expandtab

