/*
    MODULE -- signal handler

    Copyright (C) Alberto Ornaghi 

    $Id: signals.c 1096 2009-11-06 14:04:26Z alor $
*/

#include <main.h>
#include <version.h>
#include <ui.h>
#include <threads.h>
#include <capture.h>

#include <signal.h>

#include <sys/resource.h>

typedef void handler_t(int);

/* protos */

void signal_handler(void);

static handler_t *signal_handle(int signo, handler_t *handler, int flags);
static RETSIGTYPE signal_SEGV(int sig);
static RETSIGTYPE signal_TERM(int sig);
static RETSIGTYPE signal_HUP(int sig);
static RETSIGTYPE signal_PIPE(int sig);

/*************************************/

void signal_handler(void)
{
   DEBUG_MSG(D_DEBUG, "signal_handler activated");

#ifdef SIGSEGV
   signal_handle(SIGSEGV, signal_SEGV, 0);
#endif
#ifdef SIGBUS
   signal_handle(SIGBUS, signal_SEGV, 0);
#endif
#ifdef SIGINT
   signal_handle(SIGINT, signal_TERM, 0);
#endif
#ifdef SIGTERM
   signal_handle(SIGTERM, signal_TERM, 0);
#endif
#ifdef SIGCHLD
   signal(SIGCHLD, SIG_DFL);
#endif
#ifdef SIGHUP
   signal_handle(SIGHUP, signal_HUP, 0);
#endif
#ifdef SIGALRM
   /* needed by solaris */
   signal_handle(SIGALRM, SIG_IGN, 0);
#endif
#ifdef SIGPIPE
   signal_handle(SIGPIPE, signal_PIPE, 0);
#endif
}


static handler_t *signal_handle(int signo, handler_t *handler, int flags)
{
   struct sigaction act, old_act;

   act.sa_handler = handler;
   
   /* don't permit nested signal handling */
   sigfillset(&act.sa_mask); 

   act.sa_flags = flags;

   if (sigaction(signo, &act, &old_act) < 0)
      ERROR_MSG("sigaction() failed");

   return (old_act.sa_handler);
}


/*
 * received when something goes wrong ;)
 */
static RETSIGTYPE signal_SEGV(int sig)
{

   struct rlimit corelimit = {RLIM_INFINITY, RLIM_INFINITY};

#ifdef SIGBUS
   if (sig == SIGBUS)
      DEBUG_MSG(D_ERROR, " !!! BUS ERROR !!!");
   else
#endif
      DEBUG_MSG(D_ERROR, " !!! SEGMENTATION FAULT !!!");
   
   fprintf (stderr, "\nOoops !! This shouldn't happen...\n\n");
#ifdef SIGBUS
   if (sig == SIGBUS)
      fprintf (stderr, "Bus error...\n\n");
   else
#endif
      fprintf (stderr, "Segmentation Fault...\n\n");

   /* make sure the pcap handler does get closed */
   capture_close();
   
   fprintf (stderr, "\n Core dumping... (use the 'core' file for gdb analysis)\n\n");
   
   /* force the coredump */
   setrlimit(RLIMIT_CORE, &corelimit);
   signal(sig, SIG_DFL);
   raise(sig);
}



/*
 * received on CTRL+C or SIGTERM
 */
static RETSIGTYPE signal_TERM(int sig)
{
   #ifdef HAVE_STRSIGNAL
      DEBUG_MSG(D_WARNING, "Signal handler... (caught SIGNAL: %d) | %s", sig, strsignal(sig));
   #else
      DEBUG_MSG(D_WARNING, "Signal handler... (caught SIGNAL: %d)", sig);
   #endif
      
   if (sig == SIGINT) {
      fprintf(stderr, "\n\nUser requested a CTRL+C... \n\n");
   } 

   signal(sig, SIG_IGN);

   /* kill all the threads */
   my_thread_kill_all();
  
   exit(0);
}


/*
 * received on SIGHUP
 */
static RETSIGTYPE signal_HUP(int sig)
{
   #ifdef HAVE_STRSIGNAL
      DEBUG_MSG(D_WARNING, "Signal handler... (caught SIGNAL: %d) | %s", sig, strsignal(sig));
   #else
      DEBUG_MSG(D_WARNING, "Signal handler... (caught SIGNAL: %d)", sig);
   #endif
      
   /* set the global variable */
   GBL_ENV->reload = 1;
}

/*
 * received on SIGPIPE
 */
static RETSIGTYPE signal_PIPE(int sig)
{
   /* ignore the PIPE signal */
   return;
}

/* EOF */

// vim:ts=3:expandtab

