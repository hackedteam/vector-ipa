/*
    MODULE -- log module

    Copyright (C) Alberto Ornaghi

    $Id: debug.c 2859 2010-09-13 09:47:00Z alor $
*/

#include <main.h>
#include <threads.h>
#include <file.h>

#include <ctype.h>
#include <syslog.h>

#include <pcap/pcap.h>

#include <stdarg.h>
#ifdef HAVE_SYS_UTSNAME_H
   #include <sys/utsname.h>
#ifdef OS_LINUX
   #include <features.h>
#endif
#endif

/* globals */

/* protos */

void debug_init(size_t cnt);
void debug_close(void);
void debug_msg(char level, const char *message, ...);

/**********************************/

void debug_init(size_t cnt)
{
#ifdef HAVE_SYS_UTSNAME_H
   struct utsname buf;
#endif

   /* open the interface to kernel syslog */
   openlog(GBL_PROGRAM, LOG_PID, LOG_LOCAL4);


   DEBUG_MSG(D_INFO, "debug_init: Opening logging interface");

   DEBUG_MSG(D_INFO, "-> %s %s", GBL_PROGRAM, GBL_VERSION);
   #ifdef HAVE_SYS_UTSNAME_H
      uname(&buf);
      DEBUG_MSG(D_INFO, "-> running on %s %s %s", buf.sysname, buf.release, buf.machine);
   #endif
   #if defined (__GNUC__) && defined (__GNUC_MINOR__)
      DEBUG_MSG(D_INFO, "-> compiled with gcc %d.%d (%s)", __GNUC__, __GNUC_MINOR__, GCC_VERSION);
   #endif
   #if defined (__GLIBC__) && defined (__GLIBC_MINOR__)
      DEBUG_MSG(D_INFO, "-> glibc version %d.%d", __GLIBC__, __GLIBC_MINOR__);
   #endif
   DEBUG_MSG(D_INFO, "-> %s", pcap_lib_version());

   atexit(debug_close);
}


void debug_close(void)
{
   DEBUG_MSG(D_INFO, "debug_close: Closing logging interface");

   /* close the interface to the kernel syslog */
   closelog();
}


void debug_msg(char level, const char *message, ...)
{
   va_list ap;
   char buf[4096];
   char debug_message[strlen(message) + 64];
   int syslevel = LOG_INFO;

   switch(level) {
      case D_VERBOSE:
      case D_DEBUG:
         syslevel = LOG_DEBUG;
         break;
      case D_INFO:
         syslevel = LOG_INFO;
         break;
      case D_WARNING:
         syslevel = LOG_WARNING;
         break;
      case D_ERROR:
         syslevel = LOG_ERR;
         break;
   }

   /* don't log if the message is at lower priority */
   if (level > GBL_CONF->log_level)
      return;

   snprintf(debug_message, sizeof(debug_message), "[%10s][%08X] %s", my_thread_getname(MY_PTHREAD_SELF), (int)my_thread_getpid(NULL), message);

   va_start(ap, message);
   vsprintf(buf, debug_message, ap);

#ifndef DEBUG
   /* add the log to the syslog only in release */
   vsyslog(syslevel, debug_message, ap);
#endif

   va_end(ap);

#ifdef DEBUG
   printf("%s\n", buf);
#endif

   /* add to the log queue */
   if (level == D_INFO)
      log_add(RNC_LOG_INFO, buf);

   if (level == D_ERROR)
      log_add(RNC_LOG_ERROR, buf);

}


/* EOF */

// vim:ts=3:expandtab

