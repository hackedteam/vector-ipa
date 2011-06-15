/*
    MODULE -- global variables handling module

    Copyright (C) Alberto Ornaghi

    $Id: globals.c 944 2009-09-25 13:43:41Z alor $
*/

#include <main.h>

/* global vars */

struct globals *gbls;

/* proto */

void globals_alloc(void);

/*******************************************/

void globals_alloc(void)
{

   SAFE_CALLOC(gbls, 1, sizeof(struct globals));
   SAFE_CALLOC(gbls->conf, 1, sizeof(struct gbl_conf));
   SAFE_CALLOC(gbls->options, 1, sizeof(struct gbl_options));
   SAFE_CALLOC(gbls->env, 1, sizeof(struct program_env));
   SAFE_CALLOC(gbls->pcap, 1, sizeof(struct pcap_env));
   SAFE_CALLOC(gbls->lnet, 1, sizeof(struct lnet_env));
   SAFE_CALLOC(gbls->stats, 1, sizeof(struct stats_env));
   SAFE_CALLOC(gbls->net, 1, sizeof(struct net_env));
   SAFE_CALLOC(gbls->netconf, 1, sizeof(struct netconf_env));
   SAFE_CALLOC(gbls->targ, 1, sizeof(struct targets_env));

   return;
}

/* EOF */

// vim:ts=3:expandtab

