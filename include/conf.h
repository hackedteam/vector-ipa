
/* $Id: conf.h 2546 2010-06-22 10:09:01Z alor $ */

#ifndef __CONF_H
#define __CONF_H


struct conf_entry {
   char *name;
   void *value;
};

struct conf_section {
   char *title;
   struct conf_entry *entries;
};


/* exported functions */

void load_conf(void);
void load_rules(void);
void conf_dissectors(void);

#endif

/* EOF */

// vim:ts=3:expandtab

