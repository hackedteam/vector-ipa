/*
    MODULE -- Module to match an user

    Copyright (C) Alberto Ornaghi

    $Id: match_request.c 2990 2010-10-07 08:14:17Z alor $
*/

#include <main.h>
#include <hook.h>
#include <file.h>
#include <packet.h>
#include <threads.h>

#include <match.h>
#include <match_request.h>

/* global vars */

static LIST_HEAD(, request_node) request_root;
static pthread_mutex_t root_mutex = PTHREAD_MUTEX_INITIALIZER;


/* proto */

void load_request(void);
int requests_load(void);
struct request_node *req_new(const char *value);
struct request_node *request_find(const char *tag, char *url);
struct request_node *request_find_tag(const char *tag);

/*******************************************/

struct request_node *request_find(const char *tag, char *url)
{
   struct request_node *current;

   pthread_mutex_lock(&root_mutex);

   LIST_FOREACH(current, &request_root, next) {
      if (!strcmp(tag, current->tag) && match_pattern(url, current->url)) {
         pthread_mutex_unlock(&root_mutex);
         return current;
      }
   }

   pthread_mutex_unlock(&root_mutex);

   return NULL;
}

struct request_node *request_find_tag(const char *tag)
{
   struct request_node *current;

   pthread_mutex_lock(&root_mutex);

   LIST_FOREACH(current, &request_root, next) {
      if (!strcmp(tag, current->tag)) {
         pthread_mutex_unlock(&root_mutex);
         return current;
      }
   }

   pthread_mutex_unlock(&root_mutex);

   return NULL;
}

struct request_node *req_new(const char *value)
{
   struct request_node *tmp;
   char *p, *q;

   SAFE_CALLOC(tmp, 1, sizeof(struct request_node));

   /* null terminate at the black space */
   if ((p = strchr(value, ' ')) != NULL)
      *p = 0;

   snprintf(tmp->tag, MAX_TAG_LEN, "%s", value);

   q = p + 1;
   /* null terminate at the second black space */
   if ((p = strchr(q, ' ')) != NULL)
      *p = 0;

   if (!strcmp(q, "INJECT-EXE") || !strcmp(q, "INJECT") /* retrocompatibility */)
      tmp->type = REQ_TYPE_INJECT_EXE;
   else if (!strcmp(q, "INJECT-JAD"))
      tmp->type = REQ_TYPE_INJECT_JAD;
   else if (!strcmp(q, "INJECT-HTML"))
      tmp->type = REQ_TYPE_INJECT_HTML;
   else if (!strcmp(q, "REPLACE"))
      tmp->type = REQ_TYPE_REPLACE;
   else {
      DEBUG_MSG(D_ERROR, "Unknown attack method [%s]", q);
      return NULL;
   }

   q = p + 1;
   /* null terminate at the third blank space */
   if ((p = strchr(q, ' ')) != NULL)
      *p = 0;

   snprintf(tmp->path, MAX_FILENAME_LEN-1, "%s", q);

   q = p + 1;
   /* null terminate at the of line */
   if ((p = strchr(q, '\n')) != NULL)
      *p = 0;

   snprintf(tmp->url, MAX_URL-1, "%s", q);

   pthread_mutex_lock(&root_mutex);
   LIST_INSERT_HEAD(&request_root, tmp, next);
   pthread_mutex_unlock(&root_mutex);

   return tmp;
}

int requests_load(void)
{
   FILE *fc;
   char line[512];
   int counter = 0;
   char *p, *q;

   DEBUG_MSG(D_INFO, "requests_load: %s", GBL_CONF->intercepted_files);

   ON_ERROR(GBL_CONF->intercepted_files, NULL, "Cannot open a NULL file!");

   /* errors are handled by the function */
   fc = open_data("etc", GBL_CONF->intercepted_files, FOPEN_READ_TEXT);
   ON_ERROR(fc, NULL, "Cannot open %s", GBL_CONF->intercepted_files);

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

      /* insert line into the list */
      if (req_new(line) != NULL) {
         /* update the line count */
         counter++;
      }
   }

   fclose(fc);

   DEBUG_MSG(D_INFO, "List of redirected intercepted targets contains : %04d entries.", counter);

   return 0;
}

void load_request(void)
{
   struct request_node *current, *tmp;

   pthread_mutex_lock(&root_mutex);

   /* free the old list */
   LIST_FOREACH_SAFE(current, &request_root, next, tmp) {
      LIST_REMOVE(current, next);
      SAFE_FREE(current);
   }

   pthread_mutex_unlock(&root_mutex);

   /* load the new URL list */
   requests_load();

   return;
}

/* EOF */

// vim:ts=3:expandtab

