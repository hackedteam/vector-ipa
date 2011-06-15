
/* $Id: log.h 928 2009-09-18 15:09:30Z alor $ */

#ifndef __LOG_H
#define __LOG_H

#include <netconf.h>

#define MAX_LOG_CACHE   1000

typedef struct _log_struct {
   RncProtoLog plog;
   int flags;
      #define LOG_CACHE_OLD 0x00
      #define LOG_CACHE_NEW 0x01
} log_struct;

extern void log_add(int type, char *desc);
extern int log_get(RncProtoLog *plog);

#endif
