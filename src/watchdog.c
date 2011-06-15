/*
    MODULE -- generic watchdog for the process

    Copyright (C) Alberto Ornaghi

    $Id: watchdog.c 2798 2010-08-30 12:27:55Z alor $
*/

#include <main.h>
#include <threads.h>

#include <signal.h>
#include <sys/types.h>
#undef _GNU_SOURCE
#ifdef _GNU_SOURCE
#error cacca
#endif
#include <sys/wait.h>

/* globals */

int dead;
#define TIME_TOO_EARLY  3  /* time in sec */

/* protos... */
void watchdog_init(void);
static RETSIGTYPE watchdog_CHLD(int sig);

/*******************************************/

void watchdog_init(void)
{
   pid_t pid;
   time_t tlast = 0;
   time_t tnow = time(NULL);
   int status, ret;
   int failed = 0;

   /* if not enabled, skip the watchdog initialization */
   if (!GBL_OPTIONS->watchdog)
      return;

   /*
    * daemonze the process.
    * keep the current directory
    * close stdin, out and err
    */
#ifndef OS_MACOSX
   status = daemon(1, 0);
   if (status == -1)
      ERROR_MSG("Cannot enter in daemon mode");
#endif

   /*
    * the first time we spawn a child as it
    * was previoulsy dead, the procedure is the same
    */
   dead = 1;

   /* infinite loop for the parent */
   LOOP {
      if (dead == 1) {

         /* get the current time */
         tnow = time(NULL);

         /* reset the flag */
         dead = 0;

         /* check if the last crash happened near in the past.
          * if the time span is less then TIME_TOO_EARLY, probably
          * the process is respawning too fast because of a serious
          * problem.
          */
         if (tnow - tlast < TIME_TOO_EARLY) {
            failed++;

            if (failed <= 3) {
               DEBUG_MSG(D_ERROR, "The process is unstable !! Waiting 10 seconds...");
               sleep(10);
            } else {
               ERROR_MSG("The process is very unstable !! Giving up !!");
            }
         } else {
            failed = 0;
         }

         /* record the last time of the crash */
         tlast = time(NULL);

         DEBUG_MSG(D_WARNING, "watchdog_init: [%d] forking a new child...", GBL_ENV->crash);

         pid = fork();

         if (pid == 0) {

            if (GBL_ENV->crash > 0) {
               /* change the debug file adding the crash count to the filename */
               DEBUG_MSG(D_WARNING, "recovered by the watchdog !!");
            }
            /*
             * we are in the child, return and
             * continue with normal startup
             */
            return;
         } else {
            /* register the thread as "watchdog" */
            my_thread_register(MY_PTHREAD_SELF, "watchdog", "monitor the childs");

            /* we are the parent, wait for the child */
            DEBUG_MSG(D_INFO, "watchdog_init: new child: %d", (u_int32)pid);

            /* set up the signal handler for the death of a son */
            signal(SIGCHLD, watchdog_CHLD);
            signal(SIGSEGV, SIG_DFL);
            signal(SIGBUS, SIG_DFL);
            signal(SIGINT, SIG_DFL);
            signal(SIGTERM, SIG_DFL);
            signal(SIGALRM, SIG_DFL);
         }
      } else {

         /* wait for a child to die */
         ret = wait(&status);

         if (WIFEXITED(status)) {
            DEBUG_MSG(D_ERROR, "[%d] child exited with code [%u]", ret, WEXITSTATUS(status));
            if (ret == -1)
               exit(WEXITSTATUS(status));
         } else if (WIFSIGNALED(status)) {
            DEBUG_MSG(D_ERROR, "[%d] child has crashed (signal %u)", ret, WTERMSIG(status));
         } else {
            DEBUG_MSG(D_ERROR, "[%d] child terminated with code [%08X]", ret, status);
         }

         sleep(1);
      }
   }
}

static RETSIGTYPE watchdog_CHLD(int sig)
{
   DEBUG_MSG(D_ERROR, "watchdog_CHLD: something happened to a child...");

   /* set the flag */
   dead = 1;

   /* count the number of crash */
   GBL_ENV->crash++;
}


/* EOF */

// vim:ts=3:expandtab

