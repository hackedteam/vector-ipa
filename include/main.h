
/* $Id: main.h 2543 2010-06-22 07:43:36Z alor $ */

#ifndef __H
#define __H

#ifdef HAVE_CONFIG_H
   #include <config.h>
#else
   // trick for development under macos
	#include <config_static.h>
#endif

#include <sys/types.h>
#include <sys/time.h>

#include <stdio.h>
#include <stdlib.h>

#if !defined (__USE_GNU)   /* for memmem(), strsignal(), etc etc... */
   #define __USE_GNU
#endif
#ifdef OS_SOLARIS
   #define _REENTRANT      /* for strtok_r() */
#endif
#include <string.h>
#if defined (__USE_GNU)
   #undef __USE_GNU
#endif
#include <strings.h>
#include <unistd.h>
#if !defined (__USE_XOPEN) /* for strptime() */
   #define __USE_XOPEN
#endif
#include <time.h>
#if defined (__USE_XOPEN)
   #undef __USE_XOPEN
#endif

/* these are often needed... */
#include <queue.h>
#include <error.h>
#include <debug.h>
#include <log.h>
#include <_stdint.h>
#include <globals.h>
#include <_strings.h>


/* wrappers for safe memory allocation */

#define SAFE_CALLOC(x, n, s) do { \
   x = calloc(n, s); \
   ON_ERROR(x, NULL, "virtual memory exhausted"); \
} while(0)

#define SAFE_CALLOC_DEBUG(x, n, s) do { \
   DEBUG_MSG(D_INFO, "%s: calling SAFE_CALLOC [%d bytes requested]", __func__, s); \
   SAFE_CALLOC(x, n, s); \
} while (0)

#define SAFE_REALLOC(x, s) do { \
   if (x == NULL) \
      x = calloc(s, 1); \
   else \
      x = realloc(x, s); \
   ON_ERROR(x, NULL, "virtual memory exhausted"); \
} while(0)

#define SAFE_STRDUP(x, s) do{ \
   if (s) { \
      x = strdup(s); \
      ON_ERROR(x, NULL, "virtual memory exhausted"); \
   } \
}while(0)

#define SAFE_FREE(x) do{ if(x) { free(x); x = NULL; } }while(0)

#define __init __attribute__ ((constructor))

#ifndef __set_errno
#define __set_errno(e) (errno = (e))
#endif

#define LOOP for(;;)

#define EXECUTE(x, ...) do{ if(x != NULL) x( __VA_ARGS__ ); }while(0)

/* min and max */

#ifndef MIN
   #define MIN(a, b)    (((a) < (b)) ? (a) : (b))
#endif
#ifndef MAX
   #define MAX(a, b)    (((a) > (b)) ? (a) : (b))
#endif

/* time operation */

#define time_sub(a, b, result) do {                  \
   (result)->tv_sec = (a)->tv_sec - (b)->tv_sec;     \
   (result)->tv_usec = (a)->tv_usec - (b)->tv_usec;  \
   if ((result)->tv_usec < 0) {                      \
      --(result)->tv_sec;                            \
      (result)->tv_usec += 1000000;                  \
   }                                                 \
} while (0)

#define time_add(a, b, result) do {                  \
   (result)->tv_sec = (a)->tv_sec + (b)->tv_sec;     \
   (result)->tv_usec = (a)->tv_usec + (b)->tv_usec;  \
   if ((result)->tv_usec >= 1000000) {               \
      ++(result)->tv_sec;                            \
      (result)->tv_usec -= 1000000;                  \
   }                                                 \
} while (0)

/* exported by main.c */
extern void clean_exit(int errcode);
extern void drop_privs(void);

#endif

/* EOF */

// vim:ts=3:expandtab

