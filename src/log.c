/*
 MODULE -- log cache

 Copyright (C) Alberto Ornaghi

 $Id: log.c 1200 2009-12-01 09:19:08Z alor $
 */

#include <main.h>
#include <log.h>
#include <netconf.h>
#include <threads.h>

/* globals */

/* this is the array that will keep the log cache */
log_struct log_array[MAX_LOG_CACHE];
u_int log_write_pointer;
u_int log_read_pointer;
static pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;

/* protos */

void log_add(int type, char *desc);
int log_get(RncProtoLog *plog);

/************************************************/

void log_add(int type, char *desc)
{
   time_t tt;
   struct tm *ttm;

   /* get the current timestamp */
   time(&tt);
   ttm = localtime(&tt);

   /* to make the xml-rpc compliant */
   ttm->tm_year += 1900;
   ttm->tm_mon += 1;

   pthread_mutex_lock(&log_mutex);

   /* create the log in the cache */
   memcpy(&log_array[log_write_pointer].plog.timestamp, ttm, sizeof(struct mytm)); /* see the declaration of mytm */
   snprintf(log_array[log_write_pointer].plog.desc, RNC_MAX_LOG_LEN - 1, "%s", desc);
   log_array[log_write_pointer].plog.type = type;

   /* mark the log as new */
   log_array[log_write_pointer].flags = LOG_CACHE_NEW;

   /* increment the write pointer */
   log_write_pointer++;

   /*
    * rewind if we reach the end of the array
    * newer logs will overwrite the older one
    */
   if (log_write_pointer >= MAX_LOG_CACHE - 1)
      log_write_pointer = 0;

   pthread_mutex_unlock(&log_mutex);
}

int log_get(RncProtoLog *plog)
{
   if (log_array[log_read_pointer].flags == LOG_CACHE_NEW) {

      /* return the log */
      memcpy(plog, &log_array[log_read_pointer].plog, sizeof(RncProtoLog));

      /* mark it read */
      log_array[log_read_pointer].flags = LOG_CACHE_OLD;

      /* increment the read pointer */
      log_read_pointer++;

      /*
       * rewind if we reach the end of the array
       */
      if (log_read_pointer >= MAX_LOG_CACHE - 1)
         log_read_pointer = 0;

      return 1;
   }

   /* nothing to read */
   return 0;
}
